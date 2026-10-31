package cli

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/service"
	"github.com/rajasdevel/netshift/internal/store"
)

func captureOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := runtimeOutput
	var b bytes.Buffer
	runtimeOutput = &b
	t.Cleanup(func() { runtimeOutput = old })
	return &b
}

func TestSyntheticEventPreviewAndAzureRefusal(t *testing.T) {
	out := captureOutput(t)
	c, r := featureProfile(t)
	a := c.Actions["hook"]
	a.Command = []string{"hook", "literal; $(echo no)"}
	c.Actions["hook"] = a
	if err := handleTestEvent(t.Context(), c, []string{"ip_changed", "--ip", "8.8.8.8"}, r); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 || !strings.Contains(out.String(), "NETSHIFT_TEST=true") {
		t.Fatal("preview executed or lost event context")
	}
	c.Actions["cloud"] = config.ActionConfig{Type: "azure_allowlist", On: []string{"ip_changed"}}
	if handleTestEvent(t.Context(), c, []string{"ip_changed", "--ip", "8.8.8.8", "--apply"}, r) == nil || len(r.calls) != 0 {
		t.Fatal("synthetic event invoked cloud or partial command")
	}
	if err := handleTestEvent(t.Context(), c, []string{"ip_changed", "--ip", "8.8.8.8", "--action", "hook", "--apply"}, r); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0][1] != a.Command[1] {
		t.Fatal(r.calls)
	}
}
func TestStatusReportsVerificationStageAndJSONIsPreserved(t *testing.T) {
	out := captureOutput(t)
	c, _ := featureProfile(t)
	saved := store.New()
	saved.IP = "8.8.8.8"
	saved.Action("hook").Verification = &store.CheckReceipt{}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := store.Save(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := handleStatus(c, path, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "action already completed") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := handleStatus(c, path, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	var s store.State
	if json.Unmarshal(out.Bytes(), &s) != nil || s.IP != saved.IP {
		t.Fatal("JSON status changed shape")
	}
}
func TestLogReaderUsesProfileScopeAndLiteralPaths(t *testing.T) {
	s := service.Spec{Platform: "linux", Label: "netshift-example.service"}
	program, args := logCommand(s, "", 5, true)
	if program != "journalctl" || !strings.Contains(strings.Join(args, " "), "_SYSTEMD_USER_UNIT=netshift-example.service") || !strings.Contains(strings.Join(args, " "), "_UID="+strconv.Itoa(os.Getuid())) {
		t.Fatal(program, args)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "events $(literal).log")
	if err := os.WriteFile(file, []byte("{\"time\":\"now\",\"event\":\"action_completed\",\"action\":\"hook\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := captureOutput(t)
	c, _ := featureProfile(t)
	if err := handleLogs(t.Context(), c, "", []string{"--file", file}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "action_completed") {
		t.Fatal(out.String())
	}
}

// The logs command parses this format; keep it byte-compatible.
func TestLoggerFormatIsStableAndLeavesFieldsAlone(t *testing.T) {
	var out bytes.Buffer
	writes := 0
	at := time.Date(2026, 10, 30, 13, 0, 0, 5e8, time.FixedZone("CET", 3600))
	l := eventlog.Logger{Out: writerFunc(func(p []byte) (int, error) { writes++; return out.Write(p) }), Now: func() time.Time { return at }}
	fields := map[string]any{"action": "hook", "event": "caller", "apply": true}
	l.Log("action_started", fields)
	l.Log("monitor_stopped", nil)
	want := `{"action":"hook","apply":true,"event":"action_started","time":"2026-10-30T12:00:00Z"}` + "\n" +
		`{"event":"monitor_stopped","time":"2026-10-30T12:00:00Z"}` + "\n"
	if out.String() != want || writes != 2 {
		t.Fatalf("writes=%d log:\n%s", writes, out.String())
	}
	if len(fields) != 3 || fields["event"] != "caller" {
		t.Fatalf("caller's fields modified: %v", fields)
	}
	var pretty bytes.Buffer
	prettyLog(&pretty, strings.SplitN(out.String(), "\n", 2)[0], false)
	if got := pretty.String(); got != "2026-10-30T12:00:00Z  action_started  action=\"hook\"\n" {
		t.Fatalf("logs command reads %q", got)
	}
	out.Reset()
	l.Log("odd", map[string]any{"value": math.Inf(1)})
	var row map[string]string
	if err := json.Unmarshal(out.Bytes(), &row); err != nil || row["event"] != "odd" || row["log_error"] == "" {
		t.Fatalf("unencodable field: %q %v", out.String(), err)
	}
	eventlog.Logger{}.Log("discarded", fields) // A nil writer discards entries.
}
