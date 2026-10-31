package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/doctor"
	"github.com/rajasdevel/netshift/internal/service"
	"github.com/rajasdevel/netshift/internal/store"
	"github.com/rajasdevel/netshift/internal/version"
)

// profileCommands are the commands that run against a profile.
var profileCommands = []string{"validate", "identity", "once", "watch", "run", "test-event", "status", "doctor", "logs", "history", "service", "devices", "map"}

func exampleProfile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, exampleData(t, name), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExitStatus(t *testing.T) {
	old := logOutput
	logOutput = nil
	t.Cleanup(func() { logOutput = old })
	f, _ := statusCommandLine()
	for _, tc := range []struct {
		err    error
		status int
		want   []string
	}{
		{nil, 0, nil},
		{flag.ErrHelp, 0, nil},
		{cmdline.ErrUsage, 2, []string{"Commands:"}},
		{f.Errorf("unexpected arguments"), 2, []string{"netshift: status: unexpected arguments\n", "Usage: netshift --config FILE status [--json]"}},
		{&cmdline.UsageError{Message: "unknown command \"x\""}, 2, []string{`Run "netshift help" for usage.`}},
		{errors.New("doctor found failures"), 1, []string{"netshift: doctor found failures\n"}},
	} {
		var stderr bytes.Buffer
		if got := exitStatus(tc.err, &stderr); got != tc.status {
			t.Errorf("%v: status %d, want %d", tc.err, got, tc.status)
		}
		for _, want := range tc.want {
			if strings.Count(stderr.String(), want) != 1 {
				t.Errorf("%v: stderr %q lacks one %q", tc.err, stderr.String(), want)
			}
		}
		if tc.want == nil && stderr.Len() != 0 {
			t.Errorf("%v: unexpected stderr %q", tc.err, stderr.String())
		}
	}
}

// Every invalid command line exits 2 and prints its message and the
// command's usage exactly once; the flag package prints nothing itself.
func TestUsageErrorsPrintOnceAndExitTwo(t *testing.T) {
	profile := exampleProfile(t, "example.json")
	azure := exampleProfile(t, "azure.example.json")
	state := filepath.Join(t.TempDir(), "state.json")
	base := []string{"--config", profile, "--state", state}
	for _, tc := range []struct {
		args    []string
		message string
		usage   string
	}{
		{[]string{"--bogus"}, "flag provided but not defined: --bogus", ""},
		{[]string{"frobnicate"}, `unknown command "frobnicate"`, ""},
		{[]string{"status"}, "--config FILE is required", "status [--json]"},
		{append(slices.Clip(base), "status", "--bogus"), "status: flag provided but not defined: --bogus", "status [--json]"},
		{append(slices.Clip(base), "status", "extra"), `status: unexpected arguments ["extra"]`, "status [--json]"},
		{append(slices.Clip(base), "validate", "extra"), "validate: unexpected", "validate"},
		{append(slices.Clip(base), "history", "--limit", "0"), "history: --limit must be 1..10000", "history [--limit N]"},
		{append(slices.Clip(base), "history", "--limit", "x"), `invalid value "x" for flag --limit`, "history [--limit N]"},
		{append(slices.Clip(base), "logs", "--lines", "5000"), "logs: --lines must be 1..1000", "logs [--follow]"},
		{append(slices.Clip(base), "run"), "run: expected one action name", "run NAME [--apply | --dry-run]"},
		{append(slices.Clip(base), "run", "--apply", "nope"), `run: unknown action "nope"; this profile has my_network_hook`, "run NAME"},
		{append(slices.Clip(base), "once", "--apply", "--dry-run"), "once: choose --apply or --dry-run", "once [--apply | --dry-run]"},
		{append(slices.Clip(base), "once", "--apply=maybe"), `once: invalid boolean value "maybe" for --apply`, "once [--apply | --dry-run]"},
		{append(slices.Clip(base), "test-event", "--ip"), "test-event: option --ip needs a value", "test-event EVENT"},
		{append(slices.Clip(base), "test-event", "bogus_event"), "test-event: expected one event", "test-event EVENT"},
		{append(slices.Clip(base), "test-event", "ip_changed"), "test-event: ip_changed requires --ip", "test-event EVENT"},
		{append(slices.Clip(base), "test-event", "--ip", "10.0.0.1", "ip_changed"), "canonical public IPv4", "test-event EVENT"},
		{append(slices.Clip(base), "test-event", "ip_changed", "--ip", "8.8.8.8", "--action", "nope"), `test-event: unknown action "nope"`, "test-event EVENT"},
		{append(slices.Clip(base), "service", "launch"), "service: expected one operation", "service print"},
		{append(slices.Clip(base), "doctor", "now"), "doctor: unexpected", "doctor [--azure]"},
		{[]string{"init"}, `init: expected "azure"`, "init azure"},
		{[]string{"init", "azure"}, "init: needs --subscription", "init azure"},
		{[]string{"--config", profile, "init", "azure"}, "init uses --output", ""},
		{[]string{"help", "bogus"}, `help: unknown command "bogus"`, ""},
		{[]string{"help", "status", "extra"}, `help: unexpected arguments ["extra"]`, "help [COMMAND]"},
		{[]string{"version", "extra"}, `version: unexpected arguments ["extra"]`, "netshift version"},
		{append(slices.Clip(base), "history", "--limit", "for -x"), `history: invalid value "for -x" for flag --limit`, "history [--limit N]"},
		{[]string{"--config", azure, "--state", state, "test-event", "ip_changed", "--ip", "8.8.8.8", "--apply"}, "test-event: --apply runs command actions only", "test-event EVENT"},
		// Global options after the command, in every spelling.
		{[]string{"status", "--config", profile}, "status: global option --config must come before COMMAND", "status [--json]"},
		{append(slices.Clip(base), "status", "--state=x"), "status: global option --state must come before COMMAND", "status [--json]"},
		{append(slices.Clip(base), "doctor", "-verbose"), "doctor: global option --verbose must come before COMMAND", "doctor [--azure]"},
		{append(slices.Clip(base), "run", "my_network_hook", "-log-file=x"), "run: global option --log-file must come before COMMAND", "run NAME"},
		{[]string{"validate", "--version"}, "validate: global option --version must come before COMMAND", "validate"},
		{[]string{"init", "azure", "--config", profile}, "init: global option --config must come before COMMAND", "init azure"},
	} {
		out := captureOutput(t)
		err := cli(t.Context(), tc.args)
		var stderr bytes.Buffer
		if status := exitStatus(err, &stderr); status != 2 {
			t.Errorf("%q: status %d (%v)", tc.args, status, err)
			continue
		}
		text := stderr.String()
		if strings.Count(text, tc.message) != 1 || strings.Count(text, "netshift: ") != 1 {
			t.Errorf("%q: message not printed once:\n%s", tc.args, text)
		}
		if tc.usage != "" && (strings.Count(text, "Usage: ") != 1 || !strings.Contains(text, tc.usage)) {
			t.Errorf("%q: usage not printed once:\n%s", tc.args, text)
		}
		if out.Len() != 0 {
			t.Errorf("%q: wrote to stdout: %s", tc.args, out)
		}
	}
}

func TestHelpForEveryCommand(t *testing.T) {
	profile := exampleProfile(t, "example.json")
	for _, command := range append(slices.Clip(profileCommands), "init", "help", "version") {
		for _, args := range [][]string{
			{command, "-h"},
			{"--config", profile, command, "--help"},
			{"--config", profile, command, "extra", "-help"},
		} {
			out := captureOutput(t)
			err := cli(t.Context(), args)
			if !errors.Is(err, flag.ErrHelp) || exitStatus(err, &bytes.Buffer{}) != 0 {
				t.Errorf("%q: %v", args, err)
			}
			if !strings.HasPrefix(out.String(), "Usage: netshift ") || !strings.Contains(out.String(), " "+command) {
				t.Errorf("%q: help %q", args, out)
			}
		}
		out := captureOutput(t)
		if err := cli(t.Context(), []string{"help", command}); err != nil || !strings.HasPrefix(out.String(), "Usage: netshift ") {
			t.Errorf("help %s: %v %q", command, err, out)
		}
	}
	// Help for the commands that need no profile.
	for args, want := range map[string]string{"help help": "Usage: netshift help [COMMAND]", "help version": "Usage: netshift version",
		"help -h": "Usage: netshift help [COMMAND]", "version -h": "Usage: netshift version"} {
		out := captureOutput(t)
		err := cli(t.Context(), strings.Fields(args))
		if exitStatus(err, &bytes.Buffer{}) != 0 || !strings.HasPrefix(out.String(), want) {
			t.Errorf("%s: %v %q", args, err, out)
		}
	}
	out := captureOutput(t)
	if err := cli(t.Context(), []string{"version"}); err != nil || out.String() != version.Number+"\n" {
		t.Errorf("version: %v %q", err, out)
	}
	for _, args := range [][]string{{"-h"}, {"help"}} {
		out := captureOutput(t)
		err := cli(t.Context(), args)
		if exitStatus(err, &bytes.Buffer{}) != 0 || !strings.Contains(out.String(), "service print | install [--start] [--replace]") {
			t.Errorf("%q: %v %q", args, err, out)
		}
	}
	// The usage text names every command that dispatches.
	for _, command := range profileCommands {
		if !strings.Contains(usage, "\n  "+command) {
			t.Errorf("usage omits %s", command)
		}
	}
}

func TestCommandLineAcceptsOptionsAnywhere(t *testing.T) {
	type result struct {
		positional []string
		ip, value  string
		apply      bool
	}
	for _, tc := range []struct {
		args []string
		want result
	}{
		{[]string{"ip_changed", "--ip", "8.8.8.8"}, result{[]string{"ip_changed"}, "8.8.8.8", "", false}},
		{[]string{"--ip", "8.8.8.8", "ip_changed"}, result{[]string{"ip_changed"}, "8.8.8.8", "", false}},
		{[]string{"--apply", "ip_changed", "-ip=8.8.8.8"}, result{[]string{"ip_changed"}, "8.8.8.8", "", true}},
		{[]string{"--value", "--", "ip_changed", "--", "--ip", "-h"}, result{[]string{"ip_changed", "--ip", "-h"}, "", "--", false}},
		{[]string{"--value", "-h", "-", "x"}, result{[]string{"-", "x"}, "", "-h", false}},
		{[]string{"--apply=false", "a", "--value=b c", "d"}, result{[]string{"a", "d"}, "", "b c", false}},
	} {
		f, o := testEventCommandLine()
		positional, err := f.ParseArgs(tc.args)
		got := result{positional, o.ip, o.value, o.apply}
		if err != nil || !slices.Equal(got.positional, tc.want.positional) || got.ip != tc.want.ip || got.value != tc.want.value || got.apply != tc.want.apply {
			t.Errorf("%q: got %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
	f, o := runCommandLine("run")
	if positional, err := f.ParseArgs([]string{"--apply", "update_dns"}); err != nil || !o.apply || !slices.Equal(positional, []string{"update_dns"}) {
		t.Fatal("run --apply NAME misparsed", positional, err)
	}
	for _, args := range [][]string{{"--ip"}, {"--nope"}, {"---ip", "x"}, {"--apply=maybe"}} {
		f, _ := testEventCommandLine()
		var bad *cmdline.UsageError
		if _, err := f.ParseArgs(args); !errors.As(err, &bad) || !errors.Is(err, cmdline.ErrUsage) {
			t.Errorf("%q: %v", args, err)
		}
	}
	captureOutput(t)
	f, _ = testEventCommandLine()
	if _, err := f.ParseArgs([]string{"ip_changed", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func TestTestEventAcceptsEventAfterOptions(t *testing.T) {
	out := captureOutput(t)
	c, err := config.Load(exampleProfile(t, "example.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	if err = handleTestEvent(t.Context(), c, []string{"--ip", "8.8.8.8", "--previous-ip", "1.1.1.1", "ip_changed"}, r); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 || !strings.Contains(out.String(), "NETSHIFT_IP=8.8.8.8") {
		t.Fatalf("preview ran or lost the IP: %q %s", r.calls, out)
	}
}

// Only commands that bind state or cloud ownership resolve the identity, so a
// host name that cannot form one never blocks inspection or service control.
func TestIdentityResolvedOnlyWhereNeeded(t *testing.T) {
	old := config.IdentityOf
	config.IdentityOf = func(string) (string, error) { return "", errors.New("invalid identity hostname") }
	t.Cleanup(func() { config.IdentityOf = old })
	profile := exampleProfile(t, "azure.example.json")
	dir := t.TempDir()
	base := []string{"--config", profile, "--state", filepath.Join(dir, "state.json")}
	events := filepath.Join(dir, "events.log")
	if err := os.WriteFile(events, []byte("{\"event\":\"monitor_started\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"validate"}, {"status"}, {"status", "--json"}, {"history"}, {"logs", "--file", events},
		{"test-event", "ip_changed", "--ip", "8.8.8.8"}, {"service", "print"},
	} {
		captureOutput(t)
		if err := cli(t.Context(), append(slices.Clip(base), args...)); err != nil {
			t.Errorf("%q needed the identity: %v", args, err)
		}
	}
	for _, args := range [][]string{{"identity"}, {"once"}, {"run", "azure_allowlist"}, {"devices", "list"}, {"map"}} {
		captureOutput(t)
		if err := cli(t.Context(), append(slices.Clip(base), args...)); err == nil || !strings.Contains(err.Error(), "invalid identity hostname") {
			t.Errorf("%q did not resolve the identity: %v", args, err)
		}
	}
	c, err := config.Load(profile)
	if err != nil {
		t.Fatal(err)
	}
	host := service.Host{GOOS: "darwin", UID: 501, Home: dir, ConfigDir: filepath.Join(dir, "config"), Executable: profile}
	for _, operation := range []string{"stop", "status", "uninstall"} {
		captureOutput(t)
		r := &serviceRunner{loaded: true}
		err := runService(t.Context(), c, profile, filepath.Join(dir, "state.json"), []string{operation}, host, r)
		if err != nil && strings.Contains(err.Error(), "identity") {
			t.Errorf("service %s needed the identity: %v", operation, err)
		}
	}
	captureOutput(t)
	if err = runService(t.Context(), c, profile, filepath.Join(dir, "state.json"), []string{"install"}, host, &serviceRunner{}); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("install must pin the identity: %v", err)
	}
	rows := diagnose(context.Background(), c, filepath.Join(dir, "state.json"), &serviceRunner{}, stubObserver(confirmed("8.8.8.8")), false, false)
	if row := findRow(rows, "identity"); row.Status != doctor.StatusFail || findRow(rows, "saved state").Status != doctor.StatusPass {
		t.Errorf("doctor identity rows: %+v", rows)
	}
}

func TestLogsBeforeAnyLogExplains(t *testing.T) {
	captureOutput(t)
	c, err := config.Load(exampleProfile(t, "example.json"))
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "never.log")
	err = handleLogs(t.Context(), c, "", []string{"--file", missing})
	if err == nil || err.Error() != "no event log yet at "+missing+"; the watcher has not written one" {
		t.Fatal(err)
	}
}

// unreachableProfile writes a profile whose IP sources refuse connections at
// once on the loopback interface, so discovery fails without the network.
func unreachableProfile(t *testing.T) string {
	t.Helper()
	var ports []int
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
		l.Close()
	}
	profile := filepath.Join(t.TempDir(), "unreachable.json")
	text := fmt.Sprintf(`{"version":1,"profile":"unreachable","monitor":{"interval_seconds":30,"timeout_seconds":1,`+
		`"ip_sources":["https://127.0.0.1:%d/ip","https://localhost:%d/ip"]},`+
		`"actions":{"hook":{"type":"command","command":["/usr/bin/true"],"on":["ip_changed"]}}}`, ports[0], ports[1])
	if err := os.WriteFile(profile, portable([]byte(text)), 0600); err != nil {
		t.Fatal(err)
	}
	return profile
}

// --log-file receives the JSON event log and the error line of a failure;
// command output stays on standard output.
func TestLogFileRoutesOnlyTheEventLog(t *testing.T) {
	t.Cleanup(func() { logOutput = nil })
	profile := unreachableProfile(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "events.log")
	base := []string{"--config", profile, "--state", filepath.Join(dir, "state.json"), "--log-file", log}

	out := captureOutput(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- cli(ctx, append(slices.Clip(base), "watch")) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if data, _ := os.ReadFile(log); bytes.Contains(data, []byte(`"observation_unavailable"`)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch logged no failed observation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	for _, event := range []string{"monitor_started", "observation_unavailable", "monitor_stopped"} {
		if !bytes.Contains(data, []byte(`"event":"`+event+`"`)) {
			t.Fatalf("event log lacks %s:\n%s", event, data)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("event log reached standard output: %s", out)
	}

	err := cli(t.Context(), append(slices.Clip(base), "once"))
	var stderr bytes.Buffer
	if exitStatus(err, &stderr) != 1 || !strings.Contains(stderr.String(), "netshift: cannot confirm current IP") {
		t.Fatalf("once: %v %q", err, stderr.String())
	}
	if data, _ = os.ReadFile(log); !bytes.HasSuffix(data, []byte("netshift: "+err.Error()+"\n")) {
		t.Fatalf("event log lacks the error line:\n%s", data)
	}

	out.Reset()
	if err = cli(t.Context(), append(slices.Clip(base), "validate")); err != nil || !strings.Contains(out.String(), "Valid profile") {
		t.Fatalf("validate: %v %q", err, out)
	}
	if now, _ := os.ReadFile(log); !bytes.Equal(now, data) {
		t.Fatal("command output reached the event log")
	}
}

// The event log, and its rotated backup, must never be the profile or a
// state, history, or lock file, even before the state exists; the refusal
// itself must not be appended to that file.
func TestLogFileMustNotBeProfileOrState(t *testing.T) {
	t.Cleanup(func() { logOutput = nil })
	captureOutput(t)
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	writeProfileCopy(t, profile)
	original, _ := os.ReadFile(profile)
	state := filepath.Join(dir, "state.json")
	alias := filepath.Join(dir, "alias.log")
	if err := os.Link(profile, alias); err != nil {
		t.Fatal(err)
	}
	for _, log := range []string{
		profile, alias, state, store.HistoryPath(state), state + ".lock",
		filepath.Join(dir, "sub", "..", "state.json"), // the same path, uncleaned
		filepath.Join(dir, "STATE.json"),              // the same file on a case-insensitive volume
	} {
		err := cli(t.Context(), []string{"--config", profile, "--state", state, "--log-file", log, "status"})
		if err == nil || !strings.Contains(err.Error(), "--log-file") || logOutput != nil {
			t.Errorf("--log-file %s: %v", log, err)
		}
		exitStatus(err, io.Discard)
	}
	// The rotated backup is protected too: log.1 must not be the state.
	backup := filepath.Join(dir, "rotating.log")
	if err := cli(t.Context(), []string{"--config", profile, "--state", backup + ".1", "--log-file", backup, "status"}); err == nil {
		t.Error("--log-file whose backup is the state accepted")
	}
	if now, _ := os.ReadFile(profile); !bytes.Equal(now, original) {
		t.Fatal("a refused log file was written")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal created the state")
	}
	if err := cli(t.Context(), []string{"--config", profile, "--state", state, "--log-file", filepath.Join(dir, "events.log"), "status"}); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryWithoutRecordsIsEmptyArray(t *testing.T) {
	out := captureOutput(t)
	if err := handleHistory(filepath.Join(t.TempDir(), "state.json"), nil); err != nil || out.String() != "[]\n" {
		t.Fatalf("%v %q", err, out)
	}
}

// A regular-file standard error over the limit is emptied at start; a small
// one is kept, and later writes go to the start of the emptied file.
func TestBoundStandardError(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Only launchd appends standard error to a file; Windows cannot
		// truncate a file opened for appending.
		t.Skip("macOS and Linux only")
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		size  int
		empty bool
	}{{100, false}, {64, false}, {65, true}} {
		path := filepath.Join(dir, fmt.Sprint(tc.size))
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), tc.size), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		limit := int64(64)
		if tc.size == 100 {
			limit = 100
		}
		boundStandardError(f, limit)
		fmt.Fprintln(f, "netshift: next start")
		f.Close()
		data, _ := os.ReadFile(path)
		if emptied := !bytes.HasPrefix(data, []byte("x")); emptied != tc.empty || !bytes.HasSuffix(data, []byte("netshift: next start\n")) {
			t.Errorf("size %d: %q", tc.size, data)
		}
		if tc.empty && len(data) > 200 {
			t.Errorf("size %d: not bounded: %d bytes", tc.size, len(data))
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	boundStandardError(w, 0) // a pipe is not a regular file
}

func TestDashesRewritesOnlyTheOptionName(t *testing.T) {
	for in, want := range map[string]string{
		"flag provided but not defined: -x":                     "flag provided but not defined: --x",
		"flag needs an argument: -ip":                           "flag needs an argument: --ip",
		`invalid boolean value "maybe" for -apply: parse error`: `invalid boolean value "maybe" for --apply: parse error`,
		`invalid value "for -x" for flag -limit: parse error`:   `invalid value "for -x" for flag --limit: parse error`,
		`invalid value "a\" for flag -b" for flag -limit: bad`:  `invalid value "a\" for flag -b" for flag --limit: bad`,
		"bad flag syntax: ---ip":                                "bad flag syntax: ---ip",
	} {
		if got := cmdline.Dashes(in); got != want {
			t.Errorf("dashes(%q) = %q, want %q", in, got, want)
		}
	}
}
