package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// exitErrors holds real *exec.ExitError values for the exit statuses service
// managers use, made once outside any synctest bubble.
var exitErrors = sync.OnceValue(func() map[int]error {
	m := map[int]error{}
	for _, code := range []int{1, 3, 4, service.LaunchdNotFound} {
		cmd := exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code))
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd.exe", "/d", "/c", "exit "+strconv.Itoa(code))
		}
		err := cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != code {
			panic(fmt.Sprintf("exit %d: %v", code, err))
		}
		m[code] = err
	}
	return m
})

// exitFailure is the error proc.Exec returns for a program that exited
// with code and wrote message to standard error.
func exitFailure(program string, code int, message string) error {
	return fmt.Errorf("%s failed: %w: %s", program, exitErrors()[code], message)
}

// serviceRunner fakes launchctl and systemctl for one job. It records every
// call and models whether the job is loaded (or the unit active) and enabled.
type serviceRunner struct {
	label     string
	calls     [][]string
	loaded    bool
	disabled  bool
	bootedOut bool
	linger    int    // print calls that still find a booted-out job
	failOn    string // a verb that fails, such as "disable"
	answerErr error  // when set, print and is-active fail without an answer, as on a timeout
	before    func(verb string)
}

func (r *serviceRunner) Run(_ context.Context, program string, args, _ []string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{program}, args...))
	verb := args[0]
	if program == "systemctl" {
		verb = args[1]
	}
	if r.before != nil {
		r.before(verb)
	}
	if verb == r.failOn {
		return nil, errors.New(verb + " failed")
	}
	if r.answerErr != nil && (verb == "print" || verb == "is-active") {
		return nil, r.answerErr
	}
	switch verb {
	case "print":
		if r.loaded && r.bootedOut {
			if r.linger > 0 {
				r.linger--
			} else {
				r.loaded = false
			}
		}
		if !r.loaded {
			return nil, exitFailure(program, service.LaunchdNotFound, "Bad request.\nCould not find service \""+r.label+"\" in domain for user gui: 501")
		}
		return []byte("state = running"), nil
	case "print-disabled":
		value := "enabled"
		if r.disabled {
			value = "disabled"
		}
		return []byte("disabled services = {\n\t\"com.apple.example\" => disabled\n\t\"" + r.label + "\" => " + value + "\n}\n"), nil
	case "bootout":
		r.bootedOut = true
	case "bootstrap":
		if r.loaded {
			return nil, errors.New("Bootstrap failed: 5: Input/output error")
		}
		r.loaded, r.bootedOut = true, false
	case "kickstart":
		if !r.loaded {
			return nil, exitFailure(program, service.LaunchdNotFound, "Could not find service")
		}
	case "enable":
		r.disabled = false
		if slices.Contains(args, "--now") {
			r.loaded = true
		}
	case "disable":
		r.disabled = true
		if slices.Contains(args, "--now") {
			r.loaded = false
		}
	case "restart":
		r.loaded = true
	case "is-active":
		if r.loaded {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), exitFailure(program, 3, "")
	case "is-enabled":
		if r.disabled {
			return []byte("disabled\n"), exitFailure(program, 1, "")
		}
		return []byte("enabled\n"), nil
	}
	return nil, nil
}

func (r *serviceRunner) verbs() []string {
	var verbs []string
	for _, call := range r.calls {
		if call[0] == "systemctl" {
			verbs = append(verbs, call[2])
		} else {
			verbs = append(verbs, call[1])
		}
	}
	return verbs
}

// serviceFixture is a fake user account with a profile and a binary to install.
func serviceFixture(t *testing.T, goos string) (config.Config, string, service.Host) {
	t.Helper()
	exitErrors()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	host := service.Host{GOOS: goos, UID: 501, Home: home, ConfigDir: filepath.Join(home, ".config"), Executable: filepath.Join(dir, "build", "netshift"),
		Getenv: func(k string) string {
			return map[string]string{"PATH": "/usr/bin:/bin", "HTTPS_PROXY": "http://proxy.example:3128"}[k]
		}}
	for _, p := range []string{home, filepath.Dir(host.Executable), filepath.Join(dir, "project")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(host.Executable, []byte("new binary"), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "project", "home.json")
	writeProfileCopy(t, profile)
	c, err := config.Load(profile)
	if err != nil {
		t.Fatal(err)
	}
	return c, profile, host
}

func writeProfileCopy(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, exampleData(t, "example.json"), 0600); err != nil {
		t.Fatal(err)
	}
}

func runServiceArgs(t *testing.T, c config.Config, profile string, host service.Host, r proc.Runner, args ...string) error {
	t.Helper()
	return runService(context.Background(), c, profile, filepath.Join(host.Home, "state.json"), args, host, r)
}

func specFor(t *testing.T, c config.Config, profile string, host service.Host) service.Spec {
	t.Helper()
	s, err := service.NewSpec(c, profile, filepath.Join(host.Home, "state.json"), host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceInstallWithoutStartNeverActivates(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label}
			for range 2 { // a first install and a reinstall
				if err := runServiceArgs(t, c, profile, host, r, "install"); err != nil {
					t.Fatal(err)
				}
			}
			for _, verb := range r.verbs() {
				if slices.Contains([]string{"enable", "bootstrap", "kickstart", "start", "restart"}, verb) {
					t.Fatalf("install without --start activated the service: %q", r.calls)
				}
			}
			if !slices.Contains(r.verbs(), "disable") || r.loaded || !r.disabled {
				t.Fatalf("install left the service enabled: %q", r.calls)
			}
			if b, err := os.ReadFile(s.Binary); err != nil || string(b) != "new binary" {
				t.Fatal("binary not installed", err)
			}
			installed, err := config.Load(s.Config)
			if err != nil || !filepath.IsAbs(installed.Actions["my_network_hook"].Command[0]) {
				t.Fatal("installed profile not bound to this host", err)
			}
		})
	}
}

func TestServiceInstallDisablesBeforeWritingDefinition(t *testing.T) {
	captureOutput(t)
	c, profile, host := serviceFixture(t, "darwin")
	s := specFor(t, c, profile, host)
	r := &serviceRunner{label: s.Label, loaded: true}
	r.before = func(verb string) {
		if verb != "disable" {
			return
		}
		for _, p := range []string{s.Path, s.Binary, s.Config} {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s existed before the job was disabled", p)
			}
		}
	}
	if err := runServiceArgs(t, c, profile, host, r, "install"); err != nil {
		t.Fatal(err)
	}
	if r.loaded || !slices.Contains(r.verbs(), "bootout") {
		t.Fatalf("a loaded job kept running: %q", r.calls)
	}
}

func TestServiceInstallFailedDisableWritesNothing(t *testing.T) {
	captureOutput(t)
	c, profile, host := serviceFixture(t, "darwin")
	s := specFor(t, c, profile, host)
	if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label, failOn: "disable"}, "install"); err == nil {
		t.Fatal("install succeeded although disable failed")
	}
	for _, p := range []string{s.Path, s.Binary, s.Config} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written after a failed disable", p)
		}
	}
	// A reinstall keeps the previous definition when disable fails.
	if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Path)
	host.Getenv = func(string) string { return "/opt/changed/bin" }
	if runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label, failOn: "disable"}, "install") == nil {
		t.Fatal("reinstall succeeded although disable failed")
	}
	if after, _ := os.ReadFile(s.Path); !bytes.Equal(before, after) {
		t.Fatal("definition replaced after a failed disable")
	}
}

// onlyTouches fails unless every service manager call names this job.
func onlyTouches(t *testing.T, calls [][]string, allowed ...string) {
	t.Helper()
	allowed = append(allowed, "--now", "-k", "--no-pager")
	for _, call := range calls {
		operands := call[2:] // after launchctl's verb
		if call[0] == "systemctl" {
			operands = call[3:] // after --user and the verb
		}
		for _, arg := range operands {
			if !slices.Contains(allowed, arg) {
				t.Fatalf("call %q touches %q", call, arg)
			}
		}
	}
}

func TestServiceInstallStartRestartsOnlyItsJob(t *testing.T) {
	t.Run("darwin", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		target := s.Domain + "/" + s.Label
		r := &serviceRunner{label: s.Label}
		if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(r.verbs(), []string{"enable", "print", "bootstrap"}) || !r.loaded {
			t.Fatalf("first start: %q", r.calls)
		}
		// Reinstalling an unchanged definition restarts the job in place.
		r.calls = nil
		if err := runServiceArgs(t, c, profile, host, r, "--start", "install"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(r.verbs(), []string{"enable", "print", "kickstart"}) || !slices.Contains(r.calls[2], "-k") {
			t.Fatalf("unchanged restart: %q", r.calls)
		}
		onlyTouches(t, r.calls, target, s.Domain, s.Path)
	})
	t.Run("darwin changed definition waits for bootout", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label}
		if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
			t.Fatal(err)
		}
		host.Getenv = func(string) string { return "/opt/changed/bin" }
		r.calls, r.linger = nil, 3
		synctest.Test(t, func(t *testing.T) {
			if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
				t.Fatal(err)
			}
		})
		want := []string{"enable", "print", "bootout", "print", "print", "print", "print", "bootstrap"}
		if !slices.Equal(r.verbs(), want) || !r.loaded {
			t.Fatalf("changed restart: %q", r.calls)
		}
		onlyTouches(t, r.calls, s.Domain+"/"+s.Label, s.Domain, s.Path)
	})
	t.Run("darwin bootout bound", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label, loaded: true, linger: 1 << 20}
		synctest.Test(t, func(t *testing.T) {
			err := runServiceArgs(t, c, profile, host, r, "stop")
			if err == nil || !strings.Contains(err.Error(), "still loaded") {
				t.Fatalf("stop did not report a job that never unloaded: %v", err)
			}
		})
	})
	t.Run("linux", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "linux")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label, loaded: true}
		if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(r.verbs(), []string{"daemon-reload", "enable", "restart"}) || !r.loaded {
			t.Fatalf("linux start: %q", r.calls)
		}
		onlyTouches(t, r.calls, s.Label)
	})
}

func TestServiceReplaceGuard(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			out := captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install"); err != nil {
				t.Fatal(err)
			}
			original, _ := os.ReadFile(s.Path)
			if source, found, err := service.DefinitionSource(original); !found || err != nil || source != profile {
				t.Fatalf("source not recorded: %q %t %v", source, found, err)
			}
			// The same profile, reached through a hard link, is not a takeover.
			alias := filepath.Join(filepath.Dir(profile), "alias.json")
			if err := os.Link(profile, alias); err != nil {
				t.Fatal(err)
			}
			if err := runServiceArgs(t, c, alias, host, &serviceRunner{label: s.Label}, "install"); err != nil {
				t.Fatal("alias refused:", err)
			}
			if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install"); err != nil {
				t.Fatal(err)
			}

			other := filepath.Join(t.TempDir(), "elsewhere", "home.json")
			_ = os.MkdirAll(filepath.Dir(other), 0700)
			writeProfileCopy(t, other)
			r := &serviceRunner{label: s.Label, loaded: true}
			err := runServiceArgs(t, c, other, host, r, "install", "--start")
			if err == nil || !strings.Contains(err.Error(), "--replace") || !strings.Contains(err.Error(), profile) {
				t.Fatalf("took over another profile's service: %v", err)
			}
			if len(r.calls) != 0 {
				t.Fatalf("refusal touched the running service: %q", r.calls)
			}
			if now, _ := os.ReadFile(s.Path); !bytes.Equal(now, original) {
				t.Fatal("refusal changed the definition")
			}
			out.Reset()
			if err = runServiceArgs(t, c, other, host, r, "install", "--replace"); err != nil {
				t.Fatal(err)
			}
			if now, _ := os.ReadFile(s.Path); !bytes.Contains(now, []byte(other)) || !strings.Contains(out.String(), "Notice: replacing the service installed from "+profile) {
				t.Fatalf("replace: %s", out)
			}

			// Older definitions without a recorded source are replaceable, with a notice.
			legacy := bytes.ReplaceAll(original, []byte(service.SourceMarker), []byte("old comment: "))
			if err = os.WriteFile(s.Path, legacy, 0600); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err = runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "does not record its profile file") {
				t.Fatalf("no notice for a definition without a source: %s", out)
			}

			// Definitions NetShift did not write are never replaced.
			for _, replace := range []bool{false, true} {
				_ = os.WriteFile(s.Path, []byte("someone else's job"), 0600)
				args := []string{"install"}
				if replace {
					args = append(args, "--replace")
				}
				r := &serviceRunner{label: s.Label}
				if err = runServiceArgs(t, c, profile, host, r, args...); err == nil || len(r.calls) != 0 {
					t.Fatalf("replaced an unmanaged definition (replace=%t): %v %q", replace, err, r.calls)
				}
			}
			_ = os.Remove(s.Path)
			if err = os.Symlink(other, s.Path); err != nil {
				t.Fatal(err)
			}
			if err = runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install", "--replace"); err == nil {
				t.Fatal("replaced a symlinked definition")
			}
		})
	}
}

func TestServiceCommandLineErrors(t *testing.T) {
	captureOutput(t)
	c, profile, host := serviceFixture(t, "linux")
	for _, args := range [][]string{nil, {"bogus"}, {"start", "--start"}, {"stop", "--replace"}, {"install", "--apply"}, {"print", "status"}, {"install", "--bogus"}} {
		r := &serviceRunner{}
		err := runServiceArgs(t, c, profile, host, r, args...)
		var bad *cmdline.UsageError
		if !errors.As(err, &bad) || !strings.Contains(bad.Usage, "Usage: netshift --config FILE service") || len(r.calls) != 0 {
			t.Errorf("%q: %v %q", args, err, r.calls)
		}
	}
}

// When launchd gives no answer, install without --start, stop, start, and
// a restart fail instead of acting as if the job were gone.
func TestServiceUncertainLaunchdStateFails(t *testing.T) {
	timeout := fmt.Errorf("launchctl: %w", context.DeadlineExceeded)
	t.Run("install", func(t *testing.T) {
		out := captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label, loaded: true, answerErr: timeout}
		if err := runServiceArgs(t, c, profile, host, r, "install"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "Started: no") || slices.Contains(r.verbs(), "bootout") {
			t.Fatalf("reported a stopped service: %s %q", out, r.calls)
		}
		for _, p := range []string{s.Path, s.Binary, s.Config} {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s written without a stopped job", p)
			}
		}
	})
	for _, operation := range []string{"stop", "start"} {
		t.Run(operation, func(t *testing.T) {
			captureOutput(t)
			c, profile, host := serviceFixture(t, "darwin")
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label, loaded: true, answerErr: timeout}
			if err := runServiceArgs(t, c, profile, host, r, operation); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			for _, verb := range r.verbs() {
				if slices.Contains([]string{"bootout", "bootstrap", "kickstart"}, verb) {
					t.Fatalf("acted without an answer: %q", r.calls)
				}
			}
		})
	}
	t.Run("restart", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label}
		if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
			t.Fatal(err)
		}
		r.calls, r.answerErr = nil, timeout
		if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); !errors.Is(err, context.DeadlineExceeded) || !slices.Equal(r.verbs(), []string{"enable", "print"}) {
			t.Fatalf("%v %q", err, r.calls)
		}
	})
	t.Run("bootout keeps polling and returns the last error", func(t *testing.T) {
		captureOutput(t)
		c, profile, host := serviceFixture(t, "darwin")
		s := specFor(t, c, profile, host)
		r := &serviceRunner{label: s.Label, loaded: true}
		r.before = func(verb string) {
			if verb == "bootout" {
				r.answerErr = timeout // print stops answering after bootout
			}
		}
		synctest.Test(t, func(t *testing.T) {
			if err := runServiceArgs(t, c, profile, host, r, "stop"); !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "still loaded") {
				t.Fatal(err)
			}
		})
		if prints := strings.Count(strings.Join(r.verbs(), " "), "print"); prints < 10 {
			t.Fatalf("stopped polling after %d prints", prints)
		}
	})
}

// systemd --user reads units from its own XDG_CONFIG_HOME, which the shell's
// may not match; the unit, binary, and profile all follow the manager's.
func TestLinuxServiceFollowsManagerConfigHome(t *testing.T) {
	shell := func(k string) string {
		return map[string]string{"PATH": "/usr/bin", "XDG_CONFIG_HOME": "/shell/only/config"}[k]
	}
	h := service.HostFor("linux", 501, "/home/sam", "/bin/netshift", shell)
	if h.ConfigDir != "/home/sam/.config" || h.ManagerEnvironment == nil {
		t.Fatalf("linux host follows the shell: %+v", h)
	}
	if h = service.HostFor("darwin", 501, "/home/sam", "/bin/netshift", shell); h.ConfigDir != "/home/sam/Library/Application Support" || h.ManagerEnvironment != nil {
		t.Fatalf("darwin host: %+v", h)
	}

	captureOutput(t)
	c, profile, host := serviceFixture(t, "linux")
	managerConfig := filepath.Join(host.Home, "manager-config")
	queries := 0
	host.Getenv = shell
	host.ManagerEnvironment = func(ctx context.Context) ([]byte, error) {
		queries++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("unbounded manager query")
		}
		return []byte("HOME=" + host.Home + "\nXDG_CONFIG_HOME=" + managerConfig + "/\nXDG_RUNTIME_DIR=/run/user/501\n"), nil
	}
	r := &serviceRunner{}
	if err := runServiceArgs(t, c, profile, host, r, "install"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"systemd/user/netshift-example.service", "netshift/bin/netshift", "netshift/profiles/example.json"} {
		if _, err := os.Stat(filepath.Join(managerConfig, p)); err != nil || queries != 1 {
			t.Fatalf("%s not under the manager's config home: %v", p, err)
		}
	}
	unit, _ := os.ReadFile(filepath.Join(managerConfig, "systemd/user/netshift-example.service"))
	if !strings.Contains(string(unit), `"`+managerConfig+`/netshift/bin/netshift"`) {
		t.Fatalf("unit runs another binary:\n%s", unit)
	}

	// Without XDG_CONFIG_HOME in the manager, ~/.config is used.
	host.ManagerEnvironment = func(context.Context) ([]byte, error) { return []byte("HOME=" + host.Home + "\n"), nil }
	if err := runServiceArgs(t, c, profile, host, &serviceRunner{}, "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(host.Home, ".config/systemd/user/netshift-example.service")); err != nil {
		t.Fatal(err)
	}

	// An unreadable or quoted value is an error before any change.
	for _, answer := range []func(context.Context) ([]byte, error){
		func(context.Context) ([]byte, error) { return nil, errors.New("Failed to connect to bus") },
		func(context.Context) ([]byte, error) { return []byte("XDG_CONFIG_HOME=$'/odd\\npath'\n"), nil },
		func(context.Context) ([]byte, error) { return []byte("XDG_CONFIG_HOME=relative\n"), nil },
	} {
		host.ManagerEnvironment = answer
		r := &serviceRunner{}
		if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); err == nil || len(r.calls) != 0 {
			t.Fatalf("guessed the unit path: %v %q", err, r.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(host.Home, ".config/systemd/user/netshift-example.service")); err != nil {
		t.Fatal(err)
	}
}
