package doctor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

type stubObserver discovery.Observation

func (o stubObserver) Observe(context.Context, string) discovery.Observation {
	return discovery.Observation(o)
}

// confirmed is a verified, online observation of ip.
func confirmed(ip string) discovery.Observation {
	return discovery.Observation{IP: ip, Online: true, Verified: true}
}

// diagnose runs every doctor check for a synthetic Linux account with no
// service installed, beside the state file, so tests never read the real
// host's service definitions or ask its service manager.
func diagnose(ctx context.Context, c config.Config, state string, runner proc.Runner, observer discovery.Observer, azure, checks bool) []Diagnosis {
	home := filepath.Join(filepath.Dir(state), "home")
	host := service.Host{GOOS: "linux", UID: 501, Home: home, ConfigDir: filepath.Join(home, ".config"), Getenv: func(string) string { return "" }}
	d := Checkup{Config: c, State: state, Runner: runner, Observer: observer, Host: host, Azure: azure, Checks: checks}
	return d.Run(ctx)
}

func TestLaunchdDisabledFormats(t *testing.T) {
	out := []byte("disabled services = {\n\t\"dev.netshift.a\" => disabled\n\t\"dev.netshift.b\" => enabled\n\t\"dev.netshift.c\" => true\n\t\"dev.netshift.cc\" => false\n}\n")
	for label, want := range map[string]bool{"dev.netshift.a": true, "dev.netshift.b": false, "dev.netshift.c": true, "dev.netshift.cc": false, "dev.netshift.missing": false} {
		if launchdDisabled(out, label) != want {
			t.Errorf("%s: want %t", label, want)
		}
	}
}

func TestDoctorFlagsPlaceholdersAndMissingScripts(t *testing.T) {
	home := t.TempDir()
	script := filepath.Join(home, "hook.sh")
	for _, p := range []string{script, filepath.Join(home, "relative.sh")} {
		if err := os.WriteFile(p, []byte("exit 0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		argv []string
		want []string // statuses, in order
	}{
		{[]string{"/bin/sh", script, "argument"}, nil},
		{[]string{"/bin/sh", "/absolute/path/to/recipes/webhook.sh", "https://example.com/hook"}, []string{StatusFail}},
		{[]string{"/bin/sh", script, "YOUR_HOSTED_ZONE_ID"}, []string{StatusFail}},
		{[]string{"/bin/sh", filepath.Join(home, "missing.sh")}, []string{StatusFail}},
		{[]string{"/usr/bin/touch", filepath.Join(home, "created-by-hook")}, []string{StatusWarn}},
		{[]string{"/bin/sh", "relative.sh"}, []string{StatusWarn}},
		{[]string{"sh", "recipes/webhook.sh"}, []string{StatusFail}},
		{[]string{"/bin/sh", "-c", "echo relative/path"}, nil},
		{[]string{"/bin/sh", "-ec", "echo relative/path"}, nil},
		{[]string{"/bin/sh", "-eu", script}, nil},
		{[]string{"/bin/bash", "-o", "pipefail", script}, nil},
		{[]string{"/bin/sh", "+x", "--", script}, nil},
		{[]string{"python3", "-m", "http.server"}, nil},
		{[]string{"/usr/bin/printenv", "NETSHIFT_IP"}, nil},
	} {
		var got []string
		for _, p := range ArgumentProblems(tc.argv, home) {
			got = append(got, p.Status)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v, want %v (%+v)", tc.argv, got, tc.want, ArgumentProblems(tc.argv, home))
		}
	}
}

// Valid commands must never FAIL: each interpreter's options are modeled
// (code, standard input, options with values), and an option the model does
// not know makes the check give up rather than guess.
func TestDoctorScriptArgumentsPerInterpreter(t *testing.T) {
	home := t.TempDir()
	abs := func(name string) string {
		p := filepath.Join(home, name)
		if err := os.WriteFile(p, []byte("\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	js, scpt, rb, fishScript := abs("x.js"), abs("x.scpt"), abs("x.rb"), abs("s")
	for _, argv := range [][]string{
		{"osascript", "-l", "JavaScript", js},
		{"osascript", "-s", "o", scpt},
		{"node", "-r", "dotenv/config", js},
		{"node", "-p", "process.version"},
		{"ruby", "-r", "json", rb},
		{"ruby", "-W", "-e", "p 1"},
		{"python3", "-I", "-c", "import sys"},
		{"perl", "-X", "-e", "print 1"},
		{"perl", "-W", "-e", "print 1"},
		{"fish", "-C", "set x 1", fishScript},
		{"sh", "-s", "arg1"},
		{"sh", "-c", `exec "$YOUR_HOOK"`},
		{"/bin/bash", "-eo", "pipefail", js},
		{"python3", "-Wignore", "-m", "json.tool"},
		{"perl", "-I", "lib", "-e", "print 1"},
		{"ruby", "-C", home, "main.rb"}, // relative to -C, not home
		{"ruby", "-Cdir", "main.rb"},
		{"ruby", "-S", "rake"},           // searched on PATH
		{"perl", "-lne", "print"},        // -l takes optional digits: give up
		{"python3", "-Z", "relative.py"}, // unknown letter: give up
		{"bash", "--norc", "relative.sh"},
	} {
		if problems := ArgumentProblems(argv, home); len(problems) != 0 {
			t.Errorf("valid %q: %+v", argv, problems)
		}
	}
	for _, tc := range []struct {
		argv   []string
		script int
	}{
		{[]string{"node", "-r", "dotenv/config", "app.js"}, 3},
		{[]string{"ruby", "-W2", "-I", "lib", "app.rb"}, 4},
		{[]string{"python3", "-X", "dev", "-W", "error", "app.py"}, 5},
		{[]string{"perl", "-wT", "-I", "lib", "app.pl"}, 4},
		{[]string{"osascript", "-s", "s", "-l", "AppleScript", "app.scpt"}, 5},
		{[]string{"fish", "-n", "-C", "set x 1", "app.fish"}, 4},
		{[]string{"zsh", "-o", "errexit", "+O", "x", "app.sh"}, 5},
		{[]string{"ruby", "-C", "/srv", "/abs/app.rb"}, 3},
		{[]string{"sh", "--", "-app.sh"}, 2},
		{[]string{"sh", "-e"}, -1},
		{[]string{"sh", "-o"}, -1},
	} {
		if got := scriptArgument(tc.argv); got != tc.script {
			t.Errorf("%q: script %d, want %d", tc.argv, got, tc.script)
		}
	}
	for _, argv := range [][]string{{"node", "missing.js"}, {"perl", "-I", "lib", "missing.pl"}, {"python3", "-W", "ignore", "missing.py"}} {
		if problems := ArgumentProblems(argv, home); len(problems) != 1 || problems[0].Status != StatusFail {
			t.Errorf("%q: %+v", argv, problems)
		}
	}
}

// The PASS detail says only what was checked.
func TestDoctorArgumentsPassDetail(t *testing.T) {
	home := t.TempDir()
	script := filepath.Join(home, "hook.sh")
	if err := os.WriteFile(script, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for argv, want := range map[string]string{
		"/usr/bin/printenv NETSHIFT_IP":    "no placeholders; no absolute path arguments to check",
		"/bin/sh " + script:                "no placeholders; the absolute path argument exists",
		"/bin/sh " + script + " " + script: "no placeholders; all 2 absolute path arguments exist",
	} {
		c := config.Config{Actions: map[string]config.ActionConfig{"hook": {Type: config.ActionCommand, Command: strings.Fields(argv)}}}
		d := Checkup{Config: c, Host: service.Host{Home: home}}
		d.commandArguments()
		if len(d.rows) != 1 || d.rows[0].Status != StatusPass || d.rows[0].Detail != want {
			t.Errorf("%s: %+v", argv, d.rows)
		}
	}
}

func TestDoctorTableKeepsOneLinePerRow(t *testing.T) {
	var b bytes.Buffer
	rows := []Diagnosis{{Name: "saved state", Status: StatusFail, Detail: "first problem\nsecond problem\n\n  third"}}
	if err := Print(&b, rows, false); err != nil {
		t.Fatal(err)
	}
	if b.String() != "FAIL  saved state                first problem; second problem; third\n" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	if err := Print(&b, rows, true); err != nil || !strings.Contains(b.String(), `first problem\nsecond problem`) {
		t.Fatalf("JSON must keep the original detail: %s %v", b.String(), err)
	}
}
