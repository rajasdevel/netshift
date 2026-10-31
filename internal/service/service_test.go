package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
)

// exitErrors holds real *exec.ExitError values for the exit statuses service
// managers use, made once outside any synctest bubble.
var exitErrors = sync.OnceValue(func() map[int]error {
	m := map[int]error{}
	for _, code := range []int{1, 3, 4, LaunchdNotFound} {
		err := exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code)).Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != code {
			panic(fmt.Sprintf("exit %d: %v", code, err))
		}
		m[code] = err
	}
	return m
})

// exitFailure is the error proc.Exec returns for a program that exited with
// code and wrote message to standard error.
func exitFailure(program string, code int, message string) error {
	return fmt.Errorf("%s failed: %w: %s", program, exitErrors()[code], message)
}

// plistStrings returns the text of every <string> element, decoded.
func plistStrings(t *testing.T, plist []byte) []string {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(plist))
	d.Strict = true
	var out []string
	inString := false
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("invalid XML: %v\n%s", err, plist)
		}
		switch v := token.(type) {
		case xml.StartElement:
			inString = v.Name.Local == "string"
			if inString {
				out = append(out, "")
			}
		case xml.EndElement:
			inString = false
		case xml.CharData:
			if inString {
				out[len(out)-1] += string(v)
			}
		}
	}
}

func TestServiceDefinitionEscapingAndSource(t *testing.T) {
	odd := "/srv/a & b/<x>/it's \"q\"/100%/a--b/-/x-"
	s := Spec{Platform: "darwin", Label: "dev.netshift.test", Domain: "gui/501", Binary: odd + "/netshift", Config: odd + "/c.json",
		State: odd + "/s.json", Source: odd + "/home.json", Home: odd, PATH: "/usr/bin", LogPath: odd + "/l.log", ErrPath: odd + "/e.log",
		Environment: map[string]string{"HTTPS_PROXY": "http://u:p&w@proxy:3128"}}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	strs := plistStrings(t, b)
	for _, want := range []string{s.Binary, s.Config, s.State, s.LogPath, s.ErrPath, s.Home, "http://u:p&w@proxy:3128", "watch", "--apply"} {
		if !slices.Contains(strs, want) {
			t.Fatalf("plist lost %q: %q", want, strs)
		}
	}
	text := string(b)
	for _, want := range []string{"<key>WorkingDirectory</key>", "<key>StandardErrorPath</key><string>" + mustXML(t, s.ErrPath) + "</string>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plist lacks %s:\n%s", want, text)
		}
	}
	if source, found, err := DefinitionSource(b); !found || err != nil || source != s.Source {
		t.Fatalf("plist source %q %t %v", source, found, err)
	}

	for _, bad := range []string{"bell\a", "nul\x00", "invalid \xff utf-8", "\uFFFE"} {
		if _, err := xmlText(bad); err == nil {
			t.Errorf("xmlText accepted %q", bad)
		}
		bs := s
		bs.Config = bad
		if _, err := Render(bs); err == nil {
			t.Errorf("renderService accepted %q", bad)
		}
	}
	if v, err := xmlText("tab\tnew\nline \uFFFD é"); err != nil || !strings.Contains(v, "é") {
		t.Fatal(v, err)
	}

	s.Platform = "linux"
	s.Source = "/home/a\nb/%x\\--y/home.json"
	s.Binary = "/home/a \"b\"/$HOME/100%/netshift"
	b, err = Render(s)
	if err != nil {
		t.Fatal(err)
	}
	text = string(b)
	for _, want := range []string{`ExecStart="/home/a \"b\"/$$HOME/100%%/netshift"`, "WorkingDirectory=~\n", "StartLimitIntervalSec=0\n", "RestartSec=10\n", `Environment="HTTPS_PROXY=http://u:p&w@proxy:3128"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("unit lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "StartLimitBurst") || strings.Count(text, "\n# ") != 1 || !strings.HasPrefix(text, "# "+managedMarker+"\n# "+SourceMarker) {
		t.Fatalf("unit header or restart limit:\n%s", text)
	}
	if source, found, err := DefinitionSource(b); !found || err != nil || source != s.Source {
		t.Fatalf("unit source %q %t %v", source, found, err)
	}
	s.Binary = "nul\x00"
	if _, err = Render(s); err == nil {
		t.Fatal("unit accepted NUL")
	}
}

func mustXML(t *testing.T, s string) string {
	t.Helper()
	v, err := xmlText(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestServiceSpecPathsAndPlatforms(t *testing.T) {
	c := config.Config{Profile: "work"}
	host := Host{GOOS: "darwin", UID: 501, Home: "/home/sam", ConfigDir: "/home/sam/Library/Application Support", Getenv: func(string) string { return "" }}
	s, err := NewSpec(c, "/p/work.json", "/state.json", host)
	if err != nil || s.Path != "/home/sam/Library/LaunchAgents/dev.netshift.work.plist" || s.ErrPath != "/home/sam/Library/Logs/NetShift/work.stderr.log" || s.Domain != "gui/501" || s.Home != "/home/sam" {
		t.Fatal(s, err)
	}
	host.GOOS, host.ConfigDir = "linux", "/home/sam/.config"
	s, err = NewSpec(c, "/p/work.json", "/state.json", host)
	if err != nil || s.Path != "/home/sam/.config/systemd/user/netshift-work.service" || s.ErrPath != "" || s.Binary != "/home/sam/.config/netshift/bin/netshift" {
		t.Fatal(s, err)
	}
	host.GOOS = "windows"
	if _, err = NewSpec(c, "", "", host); err == nil {
		t.Fatal("claimed Windows support")
	}
	host.GOOS, host.Home = "linux", ""
	if _, err = NewSpec(c, "", "", host); err == nil {
		t.Fatal("accepted a missing home directory")
	}
}

// serviceAnswer adapts a function to Runner.
type serviceAnswer func(program string, args []string) ([]byte, error)

func (f serviceAnswer) Run(_ context.Context, program string, args, _ []string) ([]byte, error) {
	return f(program, args)
}

// Only a definite answer from the service manager says a job is not loaded;
// a timeout or another failure is an error.
func TestServiceLoadedNeedsDefiniteAnswer(t *testing.T) {
	timeout := fmt.Errorf("launchctl: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		out     string
		err     error
		loaded  bool
		failure bool
	}{
		{"state = running", nil, true, false},
		{"", exitFailure("launchctl", LaunchdNotFound, "Bad request."), false, false},
		{"", errors.New("Could not find service \"dev.netshift.x\" in domain for user gui: 501"), false, false},
		{"", timeout, false, true},
		{"", exitFailure("launchctl", 1, "Operation not permitted"), false, true},
	} {
		loaded, err := launchdLoaded(t.Context(), serviceAnswer(func(string, []string) ([]byte, error) { return []byte(tc.out), tc.err }), "gui/501/dev.netshift.x")
		if loaded != tc.loaded || (err != nil) != tc.failure {
			t.Errorf("launchctl print %q %v: loaded=%t err=%v", tc.out, tc.err, loaded, err)
		}
	}
	for _, tc := range []struct {
		out     string
		err     error
		active  bool
		failure bool
	}{
		{"active\n", nil, true, false},
		{"reloading\n", nil, true, false},
		{"activating\n", exitFailure("systemctl", 3, ""), true, false},
		{"inactive\n", exitFailure("systemctl", 3, ""), false, false},
		{"failed\n", exitFailure("systemctl", 3, ""), false, false},
		{"unknown\n", exitFailure("systemctl", 4, ""), false, false},
		{"", exitFailure("systemctl", 1, "Failed to connect to bus"), false, true},
		{"inactive\n", errors.New("exit status 3"), false, true}, // not from the program
		{"", fmt.Errorf("systemctl: %w", context.DeadlineExceeded), false, true},
	} {
		active, err := systemdActive(t.Context(), serviceAnswer(func(string, []string) ([]byte, error) { return []byte(tc.out), tc.err }), "netshift-x.service")
		if active != tc.active || (err != nil) != tc.failure {
			t.Errorf("systemctl is-active %q %v: active=%t err=%v", tc.out, tc.err, active, err)
		}
	}
}
func TestServiceDefinitionsUseNativeUserManagersAndSafeArguments(t *testing.T) {
	s := Spec{Platform: "darwin", Label: "dev.netshift.test", Binary: "/home/a & b/netshift", Config: "/home/a & b/config.json", State: "/home/a & b/state.json", PATH: "/usr/bin:/bin", LogPath: "/home/a & b/log"}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err = xml.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "a &amp; b") || !strings.Contains(string(b), "<string>--apply</string>") {
		t.Fatal(string(b))
	}
	if !strings.Contains(string(b), "<key>ProcessType</key><string>Standard</string>") || strings.Contains(string(b), "<key>LowPriorityIO</key>") {
		t.Fatal("Azure CLI must not inherit restrictive background CPU/IO throttling")
	}
	s.Platform = "linux"
	s.Binary = "/home/a b/100%/netshift"
	b, err = Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ExecStart="/home/a b/100%%/netshift"`, `Restart=on-failure`, `WantedBy=default.target`, `"watch" "--apply"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in %s", want, b)
		}
	}
	s.Platform = "windows"
	if _, err = Render(s); err == nil {
		t.Fatal("claimed Windows support")
	}
}

func TestSystemdDollarEscapingAndAzureConfigEnvironment(t *testing.T) {
	s := Spec{Platform: "linux", Label: "test", Binary: "/home/$name/netshift", Config: "/home/$name/config", State: "/home/state", PATH: "/bin", Environment: map[string]string{"AZURE_CONFIG_DIR": "/home/$name/.azure"}}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `ExecStart="/home/$$name/netshift"`) || !strings.Contains(text, `Environment="AZURE_CONFIG_DIR=/home/$name/.azure"`) {
		t.Fatal(text)
	}
}
