package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/doctor"
	"github.com/rajasdevel/netshift/internal/service"
)

// TestMain clears NETSHIFT_CONFIG, so a developer's own setting cannot change
// which profile a test loads; tests that need it use t.Setenv.
func TestMain(m *testing.M) {
	os.Unsetenv(configEnv)
	os.Exit(m.Run())
}

// NETSHIFT_CONFIG supplies the profile when --config is absent, and output
// names the file it chose; an explicit --config wins.
func TestConfigEnvironmentIsTheDefaultProfile(t *testing.T) {
	profile := exampleProfile(t, "example.json")
	state := filepath.Join(t.TempDir(), "state.json")
	t.Setenv(configEnv, profile)
	out := captureOutput(t)
	if err := cli(t.Context(), []string{"--state", state, "validate"}); err != nil {
		t.Fatal(err)
	}
	if want := `Valid profile "example" in ` + profile + " with actions: my_network_hook.\n"; out.String() != want {
		t.Fatalf("validate printed %q, want %q", out, want)
	}

	// An explicit --config wins over a variable that names a missing file.
	t.Setenv(configEnv, filepath.Join(t.TempDir(), "missing.json"))
	out.Reset()
	if err := cli(t.Context(), []string{"--config", profile, "--state", state, "validate"}); err != nil || !strings.Contains(out.String(), " in "+profile+" ") {
		t.Fatalf("--config did not win: %v %q", err, out)
	}

	// Without --config, a profile that fails to load names the variable and
	// quotes the path, so a stray space shows.
	bad := profile + " "
	if runtime.GOOS == "windows" {
		bad = profile + ".missing" // Windows ignores a trailing space in a file name
	}
	t.Setenv(configEnv, bad)
	err := cli(t.Context(), []string{"--state", state, "validate"})
	if err == nil || !strings.HasPrefix(err.Error(), configEnv+"="+strconv.Quote(bad)+": ") || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("load error does not name %s: %v", configEnv, err)
	}
	if exitStatus(err, &bytes.Buffer{}) != 1 {
		t.Fatal("a missing profile is not an invalid command line")
	}
}

// An explicit --config that is empty, as "--config $UNSET" gives, is refused
// rather than replaced by NETSHIFT_CONFIG, and so is one before init.
func TestExplicitEmptyConfigIsRefused(t *testing.T) {
	profile := exampleProfile(t, "example.json")
	t.Setenv(configEnv, profile)
	output := filepath.Join(t.TempDir(), "p.json")
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"--config=", "validate"}, "--config needs a FILE"},
		{[]string{"--config", "", "once", "--apply"}, "--config needs a FILE"},
		{[]string{"-config", " ", "validate"}, "--config needs a FILE"},
		{[]string{"--config", "", "init", "command", "--profile", "home", "--output", output}, "--config needs a FILE"},
		{[]string{"--state", "", "init", "command", "--profile", "home", "--output", output}, "init uses --output rather than --config/--state"},
	} {
		out := captureOutput(t)
		err := cli(t.Context(), tc.args)
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || strings.Count(stderr.String(), tc.message) != 1 || out.Len() != 0 {
			t.Errorf("%q: %v\n%s%s", tc.args, err, stderr.String(), out)
		}
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused init wrote a profile")
	}
}

// A hook, and anything it runs, sees NETSHIFT_CONFIG naming the profile that
// ran it, not one inherited from the caller; the caller's value is back once
// the command returns.
func TestHooksSeeTheProfileInUse(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	profile := filepath.Join(dir, "hook.json")
	text := `{"version":1,"profile":"hook","actions":{"record":{"type":"command","on":["ip_changed"],` +
		`"command":["/bin/sh","-c","printf %s \"$NETSHIFT_CONFIG\" > \"$0\"",` + strconv.Quote(seen) + `]}}}`
	if runtime.GOOS == "windows" { // a batch file that writes the variable to %1
		hook := filepath.Join(dir, "record.cmd")
		if err := os.WriteFile(hook, []byte("@echo %NETSHIFT_CONFIG%>\"%~1\"\r\n"), 0600); err != nil {
			t.Fatal(err)
		}
		text = `{"version":1,"profile":"hook","actions":{"record":{"type":"command","on":["ip_changed"],` +
			`"command":[` + strconv.Quote(hook) + `,` + strconv.Quote(seen) + `]}}}`
	}
	if err := os.WriteFile(profile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	inherited := exampleProfile(t, "example.json")
	state := filepath.Join(dir, "state.json")
	for _, args := range [][]string{
		{"--config", profile, "--state", state, "test-event", "ip_changed", "--ip", "8.8.8.8", "--apply"},
		{"--config", filepath.Join(dir, ".", "hook.json"), "--state", state, "test-event", "ip_changed", "--ip", "8.8.8.8", "--apply"},
	} {
		t.Setenv(configEnv, inherited)
		_ = os.Remove(seen)
		captureOutput(t)
		if err := cli(t.Context(), args); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(seen); err != nil || strings.TrimRight(string(data), "\r\n") != profile {
			t.Errorf("%q: hook saw %s=%q (%v), want %q", args, configEnv, data, err, profile)
		}
		if got := os.Getenv(configEnv); got != inherited {
			t.Errorf("caller's %s is %q after the command, want %q", configEnv, got, inherited)
		}
	}
}

// doctor's table names the profile file NETSHIFT_CONFIG chose; its JSON
// results keep the 0.6.0 detail, without the home directory.
func TestDoctorNamesTheProfileOnlyInTheTable(t *testing.T) {
	c, profile, host := serviceFixture(t, "linux")
	t.Setenv(configEnv, profile)
	path, err := profilePath("", doctorCommandLineOnly())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(host.Home, "state.json")
	out := captureOutput(t)
	if err = runDoctor(t.Context(), c, path, state, nil, &serviceRunner{}, stubObserver(confirmed("8.8.8.8")), host); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Profile file: "+profile+"\n") {
		t.Fatalf("table does not start with the profile file:\n%s", out)
	}
	out.Reset()
	if err = runDoctor(t.Context(), c, path, state, []string{"--json"}, &serviceRunner{}, stubObserver(confirmed("8.8.8.8")), host); err != nil {
		t.Fatal(err)
	}
	var rows []doctor.Diagnosis
	if err = json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("JSON results: %v\n%s", err, out)
	}
	if row := findRow(rows, "profile"); row.Detail != "schema and action definitions are valid" || strings.Contains(out.String(), profile) {
		t.Fatalf("JSON results name the profile file: %+v", row)
	}
}

func doctorCommandLineOnly() *cmdline.Line { f, _ := doctorCommandLine(); return f }

// A relative NETSHIFT_CONFIG is refused as an invalid invocation: it would
// name a different file, and record a different service source, in each
// directory. Without either, --config is required.
func TestConfigEnvironmentMustBeAbsolute(t *testing.T) {
	dir := t.TempDir()
	writeProfileCopy(t, filepath.Join(dir, "home.json"))
	t.Chdir(dir)
	for value, message := range map[string]string{
		"home.json":   `NETSHIFT_CONFIG must be an absolute path, not "home.json"`,
		"./home.json": `NETSHIFT_CONFIG must be an absolute path, not "./home.json"`,
		"":            "--config FILE is required, or set NETSHIFT_CONFIG",
	} {
		t.Setenv(configEnv, value)
		out := captureOutput(t)
		err := cli(t.Context(), []string{"validate"})
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || !strings.Contains(stderr.String(), message) || out.Len() != 0 {
			t.Errorf("%s=%q: %v\n%s", configEnv, value, err, stderr.String())
		}
	}
}

// Commands without a profile ignore NETSHIFT_CONFIG, even an unusable one,
// and init refuses only an explicit --config.
func TestConfigEnvironmentLeavesProfileFreeCommandsAlone(t *testing.T) {
	t.Setenv(configEnv, "relative.json")
	for _, args := range [][]string{{"help"}, {"help", "status"}, {"version"}, {"completion", "bash"}, {"status", "-h"}} {
		captureOutput(t)
		if err := cli(t.Context(), args); exitStatus(err, &bytes.Buffer{}) != 0 {
			t.Errorf("%q read %s: %v", args, configEnv, err)
		}
	}
	profile := exampleProfile(t, "example.json")
	t.Setenv(configEnv, profile)
	captureOutput(t)
	output := filepath.Join(t.TempDir(), "starter.json")
	if err := cli(t.Context(), []string{"init", "command", "--profile", "home", "--output", output}); err != nil {
		t.Fatalf("init refused because %s is set: %v", configEnv, err)
	}
	err := cli(t.Context(), []string{"--config", profile, "init", "command", "--profile", "home", "--output", output + ".2"})
	var bad *cmdline.UsageError
	if !errors.As(err, &bad) || !strings.Contains(bad.Message, "init uses --output") {
		t.Fatalf("explicit --config accepted by init: %v", err)
	}
}

// The service records the absolute profile path NETSHIFT_CONFIG chose, and
// the --replace guard still tells two such files apart.
func TestConfigEnvironmentServiceSourceAndReplaceGuard(t *testing.T) {
	// service print renders the definition that install writes, source and all.
	profile := exampleProfile(t, "example.json")
	t.Setenv(configEnv, profile)
	out := captureOutput(t)
	if err := cli(t.Context(), []string{"--state", filepath.Join(t.TempDir(), "state.json"), "service", "print"}); err != nil {
		t.Fatal(err)
	}
	source, found, err := service.DefinitionSource(out.Bytes())
	if err != nil || !found || source != profile {
		t.Fatalf("definition source %q (found %t, %v), want %s", source, found, err, profile)
	}

	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			out := captureOutput(t)
			c, first, host := serviceFixture(t, goos)
			s := specFor(t, c, first, host)
			install := func(env string, args ...string) error {
				t.Helper()
				t.Setenv(configEnv, env)
				path, err := profilePath("", validateCommandLine())
				if err != nil {
					t.Fatal(err)
				}
				return runServiceArgs(t, c, path, host, &serviceRunner{label: s.Label}, append([]string{"install"}, args...)...)
			}
			if err := install(first); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Source: "+first+"\n") {
				t.Fatalf("install did not show the profile path:\n%s", out)
			}
			second := filepath.Join(t.TempDir(), "home.json")
			writeProfileCopy(t, second)
			if err := install(second); err == nil || !strings.Contains(err.Error(), "--replace") || !strings.Contains(err.Error(), first) {
				t.Fatalf("took over the service installed from %s: %v", first, err)
			}
			if err := install(second, "--replace"); err != nil {
				t.Fatal(err)
			}
			definition, _ := os.ReadFile(s.Path)
			if source, _, _ := service.DefinitionSource(definition); source != second {
				t.Fatalf("source %q after --replace, want %s", source, second)
			}
		})
	}
}
