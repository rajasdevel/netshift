package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"unicode/utf16"

	"github.com/rajasdevel/netshift/internal/config"
)

// windowsHost is a fake Windows account with a profile and a binary to install.
func windowsHost(t *testing.T) (config.Config, string, Host) {
	t.Helper()
	exitErrors()
	dir := t.TempDir()
	home := filepath.Join(dir, "Users", "sam")
	host := Host{GOOS: "windows", Home: home, UserSID: "S-1-5-21-1000-2000-3000-1001", ConfigDir: filepath.Join(home, "AppData", "Local"),
		Executable: filepath.Join(dir, "build", "netshift.exe"), Getenv: func(string) string { return "" }}
	for _, p := range []string{home, filepath.Dir(host.Executable), filepath.Join(dir, "project")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(host.Executable, []byte("new binary"), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "project", "home.json")
	self, err := os.Executable() // an executable for the hook to resolve to
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Version: 1, Profile: "home", Actions: map[string]config.ActionConfig{
		"hook": {Type: config.ActionCommand, Command: []string{self, "--flag"}}}}
	return c, profile, host
}

// taskRunner fakes schtasks.exe for one task: whether it is registered,
// enabled, and running, and the XML it was registered with.
type taskRunner struct {
	path                         string
	calls                        [][]string
	registered, enabled, running bool
	registeredXML                string
	ended                        bool   // /End was called while queries linger
	linger                       int    // queries that still find an ended task running
	failOn                       string // a verb that fails, such as "/End"
	queryErr                     error  // when set, queries fail without an answer
	before                       func(verb string)
}

func (r *taskRunner) Run(_ context.Context, program string, args, _ []string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{program}, args...))
	if program != schtasksProgram {
		return nil, fmt.Errorf("unexpected program %s", program)
	}
	verb := args[0]
	if r.before != nil {
		r.before(verb)
	}
	if verb == r.failOn {
		return nil, exitFailure(program, 1, "ERROR: "+verb+" failed.")
	}
	if verb == "/Query" && r.queryErr != nil {
		return nil, r.queryErr
	}
	notFound := exitFailure(program, 1, "ERROR: The system cannot find the file specified.")
	named := slices.Contains(args, "/TN")
	if named && args[slices.Index(args, "/TN")+1] != r.path {
		return nil, notFound
	}
	if named && verb != "/Create" && !r.registered {
		return nil, notFound
	}
	switch {
	case verb == "/Query" && slices.Contains(args, "/XML"):
		settings := "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
		if !r.enabled {
			settings += "<Enabled>false</Enabled>"
		}
		// Exported XML is UTF-16, as some schtasks queries write.
		return utf16LE(`<?xml version="1.0" encoding="UTF-16"?><Task><Triggers><TimeTrigger><Enabled>true</Enabled></TimeTrigger></Triggers>` + settings + "</Settings></Task>"), nil
	case verb == "/Query" && slices.Contains(args, "/V") && slices.Contains(args, "CSV"):
		if r.ended && r.linger > 0 {
			if r.linger--; r.linger == 0 {
				r.running, r.ended = false, false
			}
		}
		result := "0"
		if r.running {
			result = "267009"
		}
		row := `"HOST","` + r.path + `","N/A","Ready","Interactive only","10/31/2026 1:00:00 PM","` + result + `","HOST\sam","C:\netshift.exe"` + "\r\n"
		return []byte(row + row), nil
	case verb == "/Query" && slices.Contains(args, "CSV"):
		list := `"\Microsoft\Windows\Defrag\ScheduledDefrag","N/A","Ready"` + "\r\n"
		if r.registered {
			list += `"` + r.path + `","N/A","Ready"` + "\r\n"
		}
		return []byte(list), nil
	case verb == "/Query":
		return []byte("TaskName: " + r.path + "\r\n"), nil
	case verb == "/Create":
		raw, err := os.ReadFile(args[slices.Index(args, "/XML")+1])
		if err != nil {
			return nil, err
		}
		r.registered, r.registeredXML = true, consoleText(raw)
		r.enabled = taskEnabled(r.registeredXML)
	case verb == "/Change":
		r.enabled = slices.Contains(args, "/ENABLE")
	case verb == "/Run":
		if !r.enabled {
			return nil, exitFailure(program, 1, "ERROR: The task is disabled.")
		}
		r.running = true
	case verb == "/End":
		r.ended = true
		if r.linger == 0 {
			r.running = false
		}
	case verb == "/Delete":
		r.registered, r.enabled, r.running = false, false, false
	}
	return []byte("SUCCESS"), nil
}

func (r *taskRunner) verbs() []string {
	var verbs []string
	for _, call := range r.calls {
		verb := call[1]
		if verb == "/Change" {
			verb += " " + call[len(call)-1]
		}
		verbs = append(verbs, verb)
	}
	return verbs
}

func utf16LE(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

func TestWindowsSpecPaths(t *testing.T) {
	home := t.TempDir() // an absolute path on the host running the test
	local := filepath.Join(home, "AppData", "Local")
	host := HostFor("windows", -1, home, filepath.Join(home, "netshift.exe"), func(k string) string {
		return map[string]string{"LOCALAPPDATA": local + string(filepath.Separator)}[k]
	})
	host.UserSID = "S-1-5-21-1-2-3-1001"
	if host.ConfigDir != local {
		t.Fatalf("config dir %q", host.ConfigDir)
	}
	s, err := NewSpec(config.Config{Profile: "work"}, `C:\p\work.json`, `C:\state.json`, host)
	base := filepath.Join(host.ConfigDir, "NetShift")
	if err != nil || s.Label != "NetShift-work" || taskPath(s) != `\NetShift-work` || s.UserSID != host.UserSID ||
		s.Path != filepath.Join(base, "tasks", "work.xml") || s.Binary != filepath.Join(base, "bin", "netshift.exe") ||
		s.Config != filepath.Join(base, "profiles", "work.json") || s.LogPath != filepath.Join(base, "logs", "work.log") || s.ErrPath != "" {
		t.Fatalf("%+v %v", s, err)
	}
	// A relative or missing %LOCALAPPDATA% is not guessed.
	for _, value := range []string{"", `AppData\Local`} {
		host := HostFor("windows", -1, home, "", func(string) string { return value })
		if _, err := NewSpec(config.Config{Profile: "work"}, "", "", host); err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
			t.Fatalf("%q: %v", value, err)
		}
	}
}

// taskDocument is the part of the task XML the tests read back.
type taskDocument struct {
	Triggers struct {
		Logon struct {
			UserID string `xml:"UserId"`
		} `xml:"LogonTrigger"`
		Time struct {
			StartBoundary string
			Repetition    struct{ Interval string }
		} `xml:"TimeTrigger"`
	}
	Principal struct {
		UserID              string `xml:"UserId"`
		LogonType, RunLevel string
	} `xml:"Principals>Principal"`
	Settings struct {
		MultipleInstancesPolicy, ExecutionTimeLimit, DisallowStartIfOnBatteries, StopIfGoingOnBatteries string
		Enabled                                                                                         *string
		RestartOnFailure                                                                                struct{ Interval, Count string }
	}
	Exec struct {
		Command, Arguments, WorkingDirectory string
	} `xml:"Actions>Exec"`
}

func TestTaskDefinition(t *testing.T) {
	s := Spec{Platform: "windows", Label: "NetShift-home", UserSID: "S-1-5-21-1-2-3-1001", Binary: `C:\Users\Sam Smith\AppData\Local\NetShift\bin\netshift.exe`,
		Config: `C:\Users\Sam Smith\AppData\Local\NetShift\profiles\home.json`, State: `C:\state & co\home.json`, Source: `C:\Users\Sam Smith\--x\home.json`,
		Home: `C:\Users\Sam Smith`, LogPath: `C:\logs\home.log`, PATH: `C:\Windows`, Environment: map[string]string{"HTTPS_PROXY": "http://proxy:3128"}}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var doc taskDocument
	if err = xml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if doc.Triggers.Logon.UserID != s.UserSID || doc.Principal.UserID != s.UserSID || doc.Principal.LogonType != "InteractiveToken" || doc.Principal.RunLevel != "LeastPrivilege" {
		t.Fatalf("principal and logon trigger: %+v", doc)
	}
	if doc.Triggers.Time.Repetition.Interval != "PT1M" || doc.Settings.MultipleInstancesPolicy != "IgnoreNew" || doc.Settings.ExecutionTimeLimit != "PT0S" ||
		doc.Settings.DisallowStartIfOnBatteries != "false" || doc.Settings.StopIfGoingOnBatteries != "false" || doc.Settings.RestartOnFailure.Count != "999" {
		t.Fatalf("restart and limits: %+v", doc)
	}
	if doc.Settings.Enabled != nil {
		t.Fatal("the definition fixes the enabled state; registration sets it")
	}
	want := `"C:\Users\Sam Smith\AppData\Local\NetShift\profiles\home.json"`
	if doc.Exec.Command != s.Binary || doc.Exec.WorkingDirectory != s.Home ||
		doc.Exec.Arguments != `--config `+want+` --state "C:\state & co\home.json" --log-file C:\logs\home.log watch --apply` {
		t.Fatalf("action: %+v", doc.Exec)
	}
	if strings.Contains(string(b), "proxy") {
		t.Fatal("a task cannot carry environment variables; none may appear")
	}
	if source, found, err := DefinitionSource(b); !found || err != nil || source != s.Source {
		t.Fatalf("source %q %t %v", source, found, err)
	}
	if !bytes.Contains(b, []byte(managedMarker)) {
		t.Fatal("no managed marker")
	}

	// Task Scheduler expands %VARIABLE%; XML cannot carry control characters.
	for _, bad := range []string{`C:\100%\x`, "C:\\bell\a", "C:\\nul\x00"} {
		bs := s
		bs.Config = bad
		if _, err := Render(bs); err == nil {
			t.Errorf("rendered %q", bad)
		}
	}
	s.UserSID = ""
	if _, err = Render(s); err == nil {
		t.Fatal("rendered a task without a user")
	}
}

// Go and the C runtime read these arguments back literally.
func TestWindowsArg(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "": `""`, "two words": `"two words"`, `C:\dir\`: `C:\dir\`, `C:\my dir\`: `"C:\my dir\\"`,
		`say "hi"`: `"say \"hi\""`, `a\"b`: `"a\\\"b"`, "tab\tx": "\"tab\tx\"",
	} {
		if got := windowsArg(in); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
}

func TestRegistrationXML(t *testing.T) {
	s := Spec{Platform: "windows", Label: "NetShift-home", UserSID: "S-1", Binary: `C:\n.exe`, Config: `C:\c.json`, State: `C:\s.json`, LogPath: `C:\l.log`}
	definition, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false} {
		raw, err := registrationXML(definition, enabled)
		if err != nil || !bytes.HasPrefix(raw, []byte{0xFF, 0xFE}) {
			t.Fatalf("%v %x", err, raw[:min(4, len(raw))])
		}
		text := consoleText(raw)
		if !strings.HasPrefix(text, `<?xml version="1.0" encoding="UTF-16"?>`) || strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
			t.Fatalf("declaration or line ends:\n%s", text)
		}
		var doc taskDocument
		decoder := xml.NewDecoder(strings.NewReader(strings.Replace(text, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
		if err = decoder.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if taskEnabled(text) != enabled || (doc.Settings.Enabled != nil) == enabled {
			t.Fatalf("enabled=%t: %v", enabled, doc.Settings.Enabled)
		}
	}
	if _, err := registrationXML([]byte("<plist/>"), true); err == nil {
		t.Fatal("registered a foreign definition")
	}
}

func TestSchtasksOutputParsing(t *testing.T) {
	if got := consoleText(utf16LE("<Task/>")); got != "<Task/>" {
		t.Fatalf("UTF-16 without a BOM: %q", got)
	}
	if got := consoleText(append([]byte{0xFF, 0xFE}, utf16LE("é")...)); got != "é" {
		t.Fatalf("UTF-16 with a BOM: %q", got)
	}
	if got := consoleText([]byte("plain\r\n")); got != "plain\r\n" {
		t.Fatalf("code page text: %q", got)
	}
	list := `"\Microsoft\X","N/A","Ready"` + "\r\n" + `"\NetShift-Home","N/A","Désactivée"` + "\r\n"
	if found, err := listsTask(list, `\NetShift-home`); !found || err != nil {
		t.Fatal("task names ignore case", err)
	}
	if found, err := listsTask(list, `\NetShift-work`); found || err != nil {
		t.Fatal("found a missing task", err)
	}
	row := func(name, result string) string {
		return `"H","` + name + `","N/A","En cours","Interactive","x","` + result + `","H\s"` + "\r\n"
	}
	for _, tc := range []struct {
		out     string
		running bool
		failure bool
	}{
		{row(`\NetShift-home`, "267009") + row(`\NetShift-home`, "267009"), true, false},
		{row(`\NetShift-home`, "0"), false, false},
		{row(`\NetShift-home`, "-2147020576"), false, false},
		{row(`\NetShift-home`, "N/A"), false, true},
		{row(`\NetShift-work`, "267009"), false, true},
		{"", false, true},
	} {
		running, err := lastResultRunning(tc.out, `\NetShift-home`)
		if running != tc.running || (err != nil) != tc.failure {
			t.Errorf("%q: running=%t err=%v", tc.out, running, err)
		}
	}
}

// A task is unregistered only when the full list lacks it; a failed query
// with the task listed, or a failed list, is an error.
func TestQueryTaskNeedsDefiniteAnswer(t *testing.T) {
	s := Spec{Platform: "windows", Label: "NetShift-home"}
	r := &taskRunner{path: `\NetShift-home`}
	if state, err := QueryTask(t.Context(), r, s); err != nil || state.Registered {
		t.Fatalf("missing task: %+v %v", state, err)
	}
	r = &taskRunner{path: `\NetShift-home`, registered: true, enabled: true, running: true}
	if state, err := QueryTask(t.Context(), r, s); err != nil || !state.Registered || !state.Enabled || !state.Running {
		t.Fatalf("running task: %+v %v", state, err)
	}
	r.queryErr = fmt.Errorf("schtasks.exe: %w", context.DeadlineExceeded)
	if _, err := QueryTask(t.Context(), r, s); err == nil {
		t.Fatal("a timeout was taken for an answer")
	}
	r = &taskRunner{path: `\NetShift-home`, registered: true, failOn: "/Query"}
	if _, err := QueryTask(t.Context(), r, s); err == nil {
		t.Fatal("a failed query of a listed task was taken for an answer")
	}
}

func windowsSpec(t *testing.T, c config.Config, profile string, host Host) Spec {
	t.Helper()
	s, err := NewSpec(c, profile, filepath.Join(host.Home, "state.json"), host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWindowsInstallWithoutStartRegistersDisabled(t *testing.T) {
	c, profile, host := windowsHost(t)
	s := windowsSpec(t, c, profile, host)
	r := &taskRunner{path: taskPath(s)}
	for range 2 { // a first install and a reinstall
		if err := Install(t.Context(), c, s, InstallOptions{Out: io.Discard}, host, r); err != nil {
			t.Fatal(err)
		}
		if !r.registered || r.enabled || r.running {
			t.Fatalf("task: %+v %q", r, r.calls)
		}
	}
	for _, verb := range r.verbs() {
		if verb == "/Run" || verb == "/Change /ENABLE" {
			t.Fatalf("install without --start activated the task: %q", r.calls)
		}
	}
	if b, err := os.ReadFile(s.Binary); err != nil || string(b) != "new binary" {
		t.Fatal("binary not installed", err)
	}
	installed, err := config.Load(s.Config)
	if err != nil || !filepath.IsAbs(installed.Actions["hook"].Command[0]) {
		t.Fatal("installed profile not bound to this host", err)
	}
	definition, _ := os.ReadFile(s.Path)
	if r.registeredXML == "" || !strings.Contains(r.registeredXML, "<Enabled>false</Enabled>") || bytes.Contains(definition, []byte("<Enabled>")) {
		t.Fatalf("registered:\n%s\ndefinition:\n%s", r.registeredXML, definition)
	}
	if _, err := os.Stat(strings.TrimSuffix(s.Path, ".xml") + ".register.xml"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the registration file was left behind")
	}
}

// A running watcher is disabled and ended before anything is written, so it
// cannot hold the binary open, and it is never left running without --start.
func TestWindowsInstallStopsTheTaskBeforeWriting(t *testing.T) {
	c, profile, host := windowsHost(t)
	s := windowsSpec(t, c, profile, host)
	r := &taskRunner{path: taskPath(s), registered: true, enabled: true, running: true, linger: 2}
	r.before = func(verb string) {
		if verb != "/End" {
			return
		}
		for _, p := range []string{s.Path, s.Binary, s.Config} {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s existed before the task ended", p)
			}
		}
	}
	synctest.Test(t, func(t *testing.T) {
		if err := Install(t.Context(), c, s, InstallOptions{Out: io.Discard}, host, r); err != nil {
			t.Fatal(err)
		}
	})
	if r.running || r.enabled || !slices.Contains(r.verbs(), "/End") {
		t.Fatalf("the task kept running: %q", r.calls)
	}
	if i, j := slices.Index(r.verbs(), "/Change /DISABLE"), slices.Index(r.verbs(), "/End"); i < 0 || i > j {
		t.Fatalf("ended before it was disabled: %q", r.verbs())
	}
}

func TestWindowsInstallFailedStopWritesNothing(t *testing.T) {
	c, profile, host := windowsHost(t)
	s := windowsSpec(t, c, profile, host)
	r := &taskRunner{path: taskPath(s), registered: true, enabled: true, failOn: "/Change"}
	if err := Install(t.Context(), c, s, InstallOptions{Out: io.Discard}, host, r); err == nil {
		t.Fatal("install succeeded although disable failed")
	}
	for _, p := range []string{s.Path, s.Binary, s.Config} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written after a failed disable", p)
		}
	}
}

func TestWindowsStartStopStatusAndUninstall(t *testing.T) {
	c, profile, host := windowsHost(t)
	s := windowsSpec(t, c, profile, host)
	r := &taskRunner{path: taskPath(s)}
	if err := Install(t.Context(), c, s, InstallOptions{Start: true, Out: io.Discard}, host, r); err != nil {
		t.Fatal(err)
	}
	if !r.registered || !r.enabled || !r.running {
		t.Fatalf("install --start: %+v %q", r, r.calls)
	}
	definition, _ := os.ReadFile(s.Path)
	// An unchanged reinstall with --start restarts the task.
	r.calls = nil
	if err := Install(t.Context(), c, s, InstallOptions{Start: true, Out: io.Discard}, host, r); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(s.Path); !bytes.Equal(again, definition) || !r.running ||
		!slices.Equal(r.verbs(), []string{"/Query", "/Query", "/Change /DISABLE", "/End", "/Query", "/Query", "/Create", "/Change /ENABLE", "/Run"}) {
		t.Fatalf("reinstall: %q", r.verbs())
	}
	if _, err := Control(t.Context(), r, s, "status"); err != nil {
		t.Fatalf("status of a running task: %v", err)
	}
	if _, err := Control(t.Context(), r, s, "stop"); err != nil || r.running || r.enabled {
		t.Fatalf("stop: %v %+v", err, r)
	}
	if _, err := Control(t.Context(), r, s, "status"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("status of a stopped task: %v", err)
	}
	if _, err := Control(t.Context(), r, s, "start"); err != nil || !r.running || !r.enabled {
		t.Fatalf("start: %v %+v", err, r)
	}
	var out bytes.Buffer
	if err := Uninstall(t.Context(), r, s, UninstallOptions{Out: &out}); err != nil || !r.registered || !strings.Contains(out.String(), "Would stop") {
		t.Fatalf("preview: %v %q", err, out.String())
	}
	if err := Uninstall(t.Context(), r, s, UninstallOptions{Apply: true, Out: &out}); err != nil || r.registered {
		t.Fatalf("uninstall: %v %+v", err, r)
	}
	for _, kept := range []string{s.Binary, s.Config} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("uninstall removed %s", kept)
		}
	}
	if _, err := os.Stat(s.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uninstall left the definition")
	}
	// Every call names only this task.
	for _, call := range r.calls {
		if i := slices.Index(call, "/TN"); i >= 0 && call[i+1] != taskPath(s) {
			t.Fatalf("call %q touches another task", call)
		}
	}
	// A registered task without a definition is not removed.
	r.registered = true
	if err := Uninstall(t.Context(), r, s, UninstallOptions{Apply: true, Out: &out}); err == nil || !r.registered {
		t.Fatalf("removed a task without a definition: %v", err)
	}
}
