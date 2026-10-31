package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
	"runtime"
)

func featureEngine(t testing.TB) (*Engine, *fakeRunner, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	c := config.Config{Version: 1, Profile: "features", Actions: map[string]config.ActionConfig{"hook": {Type: "command", Command: []string{"hook"}, On: []string{"ip_changed"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	return &Engine{Config: c, State: store.New(), Apply: true, Runner: r, Now: func() time.Time { return now }, Save: func(*store.State) error { return nil }}, r, &now
}
func TestPostActionFailureRetriesOnlyChecksAcrossRestart(t *testing.T) {
	e, r, now := featureEngine(t)
	a := e.Config.Actions["hook"]
	a.Checks = []config.CheckConfig{{Name: "database", Type: "tcp", Address: "127.0.0.1:5432", TimeoutSeconds: 1}}
	e.Config.Actions["hook"] = a
	calls := 0
	e.Check = func(context.Context, config.CheckConfig) error { calls++; return errors.New("not ready") }
	if e.step(t.Context(), confirmed("8.8.8.8"), acceptAtOnce, reapplyStale) == nil {
		t.Fatal("missing failed verification")
	}
	if len(r.calls) != 1 || e.State.Action("hook").Verification == nil {
		t.Fatal("successful action receipt missing")
	}
	// Simulate a process restart with only persisted state.
	data, _ := json.Marshal(e.State)
	var restored store.State
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	e.State = &restored
	*now = now.Add(time.Minute)
	e.Check = func(context.Context, config.CheckConfig) error { calls++; return nil }
	if err := e.step(t.Context(), confirmed("8.8.8.8"), acceptConfirmed, reapplyStale); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || calls != 2 || e.State.Action("hook").Pending != nil || e.State.Action("hook").Verification != nil {
		t.Fatal("action repeated or verification not completed")
	}
	if !e.State.Action("hook").LastChecks[0].Reachable {
		t.Fatal("check result not recorded")
	}
}
func TestNewIPInvalidatesCheckReceipt(t *testing.T) {
	e, r, now := featureEngine(t)
	a := e.Config.Actions["hook"]
	a.Checks = []config.CheckConfig{{Name: "ready", Type: "tcp", Address: "127.0.0.1:9", TimeoutSeconds: 1}}
	e.Config.Actions["hook"] = a
	e.Check = func(context.Context, config.CheckConfig) error { return errors.New("no") }
	_ = e.step(t.Context(), confirmed("8.8.8.8"), acceptAtOnce, reapplyStale)
	*now = now.Add(time.Minute)
	_ = e.step(t.Context(), confirmed("1.1.1.1"), acceptAtOnce, reapplyStale)
	if len(r.calls) != 2 || e.State.Action("hook").Verification.Event.IP != "1.1.1.1" {
		t.Fatal("new network reused an old action receipt")
	}
}
func TestProbeTCPHTTPStatusRedirectAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp := config.CheckConfig{Name: "tcp", Type: "tcp", Address: listener.Addr().String(), TimeoutSeconds: 1}
	if err := Probe(t.Context(), tcp); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if Probe(t.Context(), tcp) == nil {
		t.Fatal("closed port reported reachable")
	}
	redirects := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/target")
			w.WriteHeader(302)
		case "/target":
			redirects++
		case "/wait":
			<-r.Context().Done()
		default:
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	check := config.CheckConfig{Name: "web", Type: "http", URL: server.URL, TimeoutSeconds: 1, ExpectedStatus: 204}
	if err := Probe(t.Context(), check); err != nil {
		t.Fatal(err)
	}
	check.URL = server.URL + "/redirect"
	if Probe(t.Context(), check) == nil || redirects != 0 {
		t.Fatal("redirect followed or accepted")
	}
	check.URL = server.URL + "/wait"
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := Probe(ctx, check); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestCheckAndNotificationValidation(t *testing.T) {
	bad := [][]config.CheckConfig{{{Name: "x", Type: "tcp", Address: "localhost:0"}}, {{Name: "x", Type: "http", URL: "https://user:password@example.com"}}, {{Name: "x", Type: "http", URL: "ftp://example.com"}}, {{Name: "x", Type: "tcp", Address: "localhost:22", TimeoutSeconds: 31}}, {{Name: "x", Type: "tcp", Address: "localhost:22"}, {Name: "x", Type: "tcp", Address: "localhost:23"}}}
	for _, checks := range bad {
		if config.ValidateChecks(checks) == nil {
			t.Fatal(checks)
		}
	}
	if config.ValidateNotifications(&config.NotificationConfig{AfterFailures: -1}) == nil {
		t.Fatal("bad threshold")
	}
	e, _, _ := featureEngine(t)
	e.Config.Monitor.ResumeAfterSeconds = 1
	if e.Config.Validate() == nil {
		t.Fatal("unbounded resume timer")
	}
}
func TestNotificationsThresholdRecoveryAndNoRepeat(t *testing.T) {
	e, _, now := featureEngine(t)
	e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 3, CooldownSeconds: 30}
	var messages []string
	e.Notify = func(_ context.Context, _, body string) error { messages = append(messages, body); return nil }
	for range 2 {
		e.recordOutcome("hook", errors.New("fail"))
		if err := e.flushNotifications(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if len(messages) != 0 {
		t.Fatal("alerted too early")
	}
	e.recordOutcome("hook", errors.New("fail"))
	_ = e.flushNotifications(t.Context())
	for range 20 {
		*now = now.Add(time.Minute)
		e.recordOutcome("hook", errors.New("fail"))
		_ = e.flushNotifications(t.Context())
	}
	if len(messages) != 1 {
		t.Fatal("repeated a failure notification", messages)
	}
	e.recordOutcome("hook", nil)
	_ = e.flushNotifications(t.Context())
	_ = e.flushNotifications(t.Context())
	if len(messages) != 2 || !strings.Contains(messages[1], "recovered") {
		t.Fatal(messages)
	}
}
func TestUnavailableNotifierIsBoundedAndDoesNotBlockAction(t *testing.T) {
	e, _, now := featureEngine(t)
	e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 1, CooldownSeconds: 60}
	calls := 0
	e.Notify = func(context.Context, string, string) error { calls++; return errors.New("no desktop") }
	e.recordOutcome("hook", errors.New("failed"))
	for range 20 {
		if err := e.flushNotifications(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("helper was repeatedly spawned")
	}
	*now = now.Add(time.Minute)
	_ = e.flushNotifications(t.Context())
	if calls != 2 {
		t.Fatal(calls)
	}
	e.recordOutcome("hook", nil)
	_ = e.flushNotifications(t.Context())
	if calls != 2 {
		t.Fatal("sent a recovery for a failure never delivered")
	}
}
func TestNotificationArgumentsRemainLiteral(t *testing.T) {
	body := `" & do shell script "touch /tmp/never"`
	for _, platform := range []string{"darwin", "linux"} {
		_, args, err := NotificationCommand(platform, "NetShift", body)
		if err != nil || args[len(args)-1] != body {
			t.Fatal(args, err)
		}
		if platform == "darwin" && strings.Contains(args[1], body) {
			t.Fatal("body interpolated into script")
		}
	}
}
func TestLocalEventsAreOptInEdgeTriggeredAndBaselineOnly(t *testing.T) {
	e, _, now := featureEngine(t)
	a := e.Config.Actions["hook"]
	a.On = []string{"interface_changed", "monitor_resumed"}
	e.Config.Actions["hook"] = a
	value := "wifi=10.0.0.1/24"
	reads := 0
	e.Interfaces = func() (string, error) { reads++; return value, nil }
	e.observeLocal(time.Time{})
	if reads != 0 {
		t.Fatal("disabled source did work")
	}
	e.Config.Monitor.InterfaceChanges = true
	e.Config.Monitor.ResumeAfterSeconds = 300
	e.observeLocal(time.Time{})
	if e.State.LastEvent != nil {
		t.Fatal("baseline emitted event")
	}
	e.observeLocal(time.Time{})
	if e.State.LastEvent != nil {
		t.Fatal("unchanged source emitted event")
	}
	value = "wifi=10.0.1.1/24"
	e.observeLocal(time.Time{})
	if e.State.LastEvent.Type != "interface_changed" {
		t.Fatal(e.State.LastEvent)
	}
	e.State.LastEvent = nil
	e.observeLocal(now.Add(-301 * time.Second))
	if e.State.LastEvent.Type != "monitor_resumed" {
		t.Fatal("missed resume gap")
	}
}
func TestQuietCyclesDoNotWriteSpawnProbeOrNotify(t *testing.T) {
	e, r, _ := featureEngine(t)
	e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 3, CooldownSeconds: 60}
	e.State.IP = "8.8.8.8"
	e.State.Connectivity = "online"
	a := e.Config.Actions["hook"]
	a.Checks = []config.CheckConfig{{Name: "x", Type: "tcp", Address: "127.0.0.1:9", TimeoutSeconds: 1}}
	e.Config.Actions["hook"] = a
	writes, probes, notices := 0, 0, 0
	e.Save = func(*store.State) error { writes++; return nil }
	e.Check = func(context.Context, config.CheckConfig) error { probes++; return nil }
	e.Notify = func(context.Context, string, string) error { notices++; return nil }
	if err := e.step(t.Context(), confirmed(e.State.IP), acceptConfirmed, reapplyStale); err != nil {
		t.Fatal(err)
	}
	writes = 0
	for range 1000 {
		if err := e.step(t.Context(), confirmed(e.State.IP), acceptConfirmed, reapplyStale); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 0 || probes != 0 || notices != 0 || len(r.calls) != 0 {
		t.Fatal(writes, probes, notices, len(r.calls))
	}
}
func BenchmarkQuietStep(b *testing.B) {
	e, _, _ := featureEngine(b)
	e.State.IP = "8.8.8.8"
	e.State.Connectivity = "online"
	e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 3, CooldownSeconds: 300}
	e.cachedNames = config.ActionNames(e.Config)
	e.cachedActions = map[string]string{"hook": config.Fingerprint(e.Config.Actions["hook"])}
	ctx := b.Context()
	_ = e.step(ctx, confirmed(e.State.IP), acceptConfirmed, reapplyStale)
	b.ReportAllocs()
	for b.Loop() {
		_ = e.step(ctx, confirmed(e.State.IP), acceptConfirmed, reapplyStale)
	}
}

type fixedObserver struct{ value discovery.Observation }

func (f fixedObserver) Observe(context.Context, string) discovery.Observation { return f.value }

func BenchmarkQuietAzureProfile(b *testing.B) {
	e, _, _ := featureEngine(b)
	targets := make([]config.Target, 19)
	for i := range targets {
		targets[i] = fixtureTarget("target-"+strconv.Itoa(i), "nsg")
	}
	e.Config.Actions = map[string]config.ActionConfig{"allow": {Type: "azure_allowlist", Targets: targets}}
	if err := e.Config.Validate(); err != nil {
		b.Fatal(err)
	}
	e.State.IP = "8.8.8.8"
	e.State.Connectivity = "online"
	a := e.Config.Actions["allow"]
	s := e.State.Action("allow")
	s.AppliedIP = e.State.IP
	s.AppliedFingerprint = config.Fingerprint(a)
	for _, target := range targets {
		s.Target(target.ID).HistoryInitialized = true
		s.Target(target.ID).AppliedIP = e.State.IP
	}
	e.cachedNames = config.ActionNames(e.Config)
	e.cachedActions = map[string]string{"allow": config.Fingerprint(a)}
	ctx := b.Context()
	_ = e.step(ctx, confirmed(e.State.IP), acceptConfirmed, reapplyStale)
	b.ReportAllocs()
	for b.Loop() {
		_ = e.step(ctx, confirmed(e.State.IP), acceptConfirmed, reapplyStale)
	}
}

func TestPendingChecksStillObserveRemoteRetirementAtReconcileInterval(t *testing.T) {
	e, cloud := deviceFixture(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { return now }
	a := e.Config.Actions["allow"]
	a.Devices.ReconcileSeconds = 60
	a.Checks = []config.CheckConfig{{Name: "db", Type: "tcp", Address: "127.0.0.1:5432", TimeoutSeconds: 1}}
	e.Config.Actions["allow"] = a
	e.State.IP = "8.8.4.4"
	event := store.Event{Type: "ip_changed", IP: e.State.IP, At: now}
	probes := 0
	e.Check = func(context.Context, config.CheckConfig) error { probes++; return errors.New("blocked") }
	if e.executeAction(t.Context(), "allow", a, event, false) == nil {
		t.Fatal("expected verification failure")
	}
	other := deviceEngine(t, e.Config, cloud, "sam@desktop")
	if err := other.retireDevice(t.Context(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	if err := e.executeAction(t.Context(), "allow", a, event, false); err != nil {
		t.Fatal(err)
	}
	if !e.State.Action("allow").Retired || e.State.Action("allow").Verification != nil || probes != 1 {
		t.Fatal("verification retries hid remote retirement")
	}
	e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 1, CooldownSeconds: 30}
	e.State.Action("allow").Notice = &store.NotificationState{Alerted: true}
	e.recordOutcome("allow", nil)
	if e.State.Action("allow").Notice != nil {
		t.Fatal("retirement generated a misleading recovery notification")
	}
}

// run NAME must not consume an IP change that other actions subscribe to.
func TestManualRunLeavesIPChangeEventsToWatch(t *testing.T) {
	e, r, _ := featureEngine(t)
	e.Config.Actions["other"] = config.ActionConfig{Type: "command", Command: []string{"other"}, On: []string{"ip_changed"}, TimeoutSeconds: 10}
	e.Observer = fixedObserver{confirmed("8.8.8.8")}
	if err := e.Manual(t.Context(), "hook"); err != nil {
		t.Fatal(err)
	}
	if e.State.IP != "" || e.State.Action("hook").AppliedIP != "8.8.8.8" {
		t.Fatalf("manual run changed observed state: ip=%q", e.State.IP)
	}
	if err := e.step(t.Context(), confirmed("8.8.8.8"), acceptAtOnce, reapplyStale); err != nil {
		t.Fatal(err)
	}
	ran := map[string]int{}
	for _, call := range r.calls {
		ran[call[0]]++
	}
	if ran["other"] != 1 || e.State.LastEvent == nil || e.State.LastEvent.Type != "ip_changed" {
		t.Fatalf("other subscriber missed ip_changed: calls=%v", r.calls)
	}
}

// Stopping the watcher, or Ctrl-C during run NAME, while a hook runs leaves
// the action pending for the next start, without backoff or a false failure
// notification.
func TestCancellationIsNotAnActionFailure(t *testing.T) {
	for name, run := range map[string]func(context.Context, *Engine) error{
		"watch step": func(ctx context.Context, e *Engine) error {
			return e.step(ctx, confirmed("8.8.8.8"), acceptAtOnce, reapplyStale)
		},
		"run NAME": func(ctx context.Context, e *Engine) error {
			e.Observer = fixedObserver{confirmed("8.8.8.8")}
			return e.Manual(ctx, "hook")
		},
	} {
		e, _, _ := featureEngine(t)
		e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 1, CooldownSeconds: 30}
		notified := 0
		e.Notify = func(context.Context, string, string) error { notified++; return nil }
		ctx, cancel := context.WithCancel(t.Context())
		e.Runner = runnerFunc(func(ctx context.Context, _ string, _, _ []string) ([]byte, error) {
			cancel()
			return nil, ctx.Err()
		})
		if err := run(ctx, e); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: %v", name, err)
		}
		s := e.State.Action("hook")
		if s.Pending == nil || s.Attempts != 0 || !s.RetryAt.IsZero() || s.LastError != "" || s.Notice != nil || notified != 0 {
			t.Fatalf("%s: cancellation recorded as failure: %+v notified=%d", name, s, notified)
		}
	}
}

func TestWatchSavesQueuedLocalEventOnShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, _ := featureEngine(t)
		e.Now = nil
		e.Config.Monitor.InterfaceChanges = true
		a := e.Config.Actions["hook"]
		a.On = append(a.On, "interface_changed")
		e.Config.Actions["hook"] = a
		snapshots := []string{"en0=192.0.2.1/24", "en0=192.0.2.2/24"}
		e.Interfaces = func() (string, error) {
			value := snapshots[0]
			if len(snapshots) > 1 {
				snapshots = snapshots[1:]
			}
			return value, nil
		}
		var saved store.State
		e.Save = func(s *store.State) error {
			data, _ := json.Marshal(s)
			saved = store.State{}
			return json.Unmarshal(data, &saved)
		}
		ctx, cancel := context.WithCancel(t.Context())
		polls := 0
		e.Observer = observerFunc(func(context.Context, string) discovery.Observation {
			if polls++; polls == 2 {
				cancel() // Stop arrives after the interface event was queued.
				return discovery.Observation{Err: context.Canceled}
			}
			return confirmed("8.8.8.8")
		})
		if err := e.Watch(ctx); err != nil {
			t.Fatal(err)
		}
		if saved.LastEvent == nil || saved.LastEvent.Type != "interface_changed" || saved.Actions["hook"].Pending == nil {
			t.Fatalf("queued local event was not saved: %+v", saved.LastEvent)
		}
	})
}

func TestOutageWithChangingErrorDetailStaysQuiet(t *testing.T) {
	refused := func(addr string) error {
		return &url.Error{Op: "Get", URL: "https://a.example", Err: &net.OpError{Op: "dial", Net: "tcp4",
			Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 443}, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
	}
	one, two := discovery.FailureReason("https://a.example/ip", refused("192.0.2.1")), discovery.FailureReason("https://a.example/ip", refused("192.0.2.2"))
	if one != two || one != "a.example: dial: connection refused" {
		t.Fatalf("unstable reasons: %q %q", one, two)
	}
	timeout := &url.Error{Op: "Get", URL: "https://a.example", Err: context.DeadlineExceeded}
	if got := discovery.FailureReason("https://a.example", timeout); got != "a.example: timed out" {
		t.Fatal(got)
	}
	if got := discovery.FailureReason("https://a.example", &net.DNSError{Err: "no such host", Name: "a.example", Server: "192.0.2.53:53"}); got != "a.example: DNS lookup failed" {
		t.Fatal(got)
	}

	e, _, _ := featureEngine(t)
	writes := 0
	e.Save = func(*store.State) error { writes++; return nil }
	var logged bytes.Buffer
	e.Log = eventlog.Logger{Out: &logged}
	for i := range 10 {
		o := discovery.Observation{Err: fmt.Errorf("attempt %d", i), Reason: "IP discovery unavailable: a.example: timed out"}
		if err := e.step(t.Context(), o, acceptConfirmed, reapplyStale); err != nil {
			t.Fatal(err)
		}
	}
	// One write per offline confirmation, then nothing while the reason holds.
	if writes != e.Config.Monitor.OfflineConfirmations || strings.Count(logged.String(), "observation_unavailable") != 1 {
		t.Fatalf("writes=%d log=%s", writes, logged.String())
	}
}

// The engine's event log uses the engine clock, so log and state times agree.
func TestEngineLogUsesEngineClock(t *testing.T) {
	e, _, now := featureEngine(t)
	*now = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var out bytes.Buffer
	e.Log = eventlog.Logger{Out: &out}
	if err := e.step(t.Context(), confirmed("8.8.8.8"), acceptAtOnce, reapplyStale); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil || row["time"] != "2030-01-02T03:04:05Z" {
			t.Fatalf("entry %q: %v", line, err)
		}
	}
	if len(lines) < 3 { // ip_changed, action_started, action_completed
		t.Fatalf("log: %s", out.String())
	}
}

func TestRunnerOutputLimitIsConfigurable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh; proc's Windows tests cover output limits")
	}
	script := []string{"-c", "head -c 1500000 /dev/zero"}
	if _, err := (proc.Exec{}).Run(t.Context(), "/bin/sh", script, nil); err == nil || !strings.Contains(err.Error(), "exceeded the output limit") {
		t.Fatalf("default limit: %v", err)
	}
	data, err := (proc.Exec{MaxOutput: 2 << 20}).Run(t.Context(), "/bin/sh", script, nil)
	if err != nil || len(data) != 1500000 {
		t.Fatalf("raised limit: len=%d err=%v", len(data), err)
	}
	if _, err = (proc.Exec{MaxOutput: 1000}).Run(t.Context(), "/bin/sh", []string{"-c", "head -c 1001 /dev/zero"}, nil); err == nil {
		t.Fatal("lowered limit not enforced")
	}
}

// Programs start in the home directory whether NetShift runs from a shell,
// launchd, or systemd, and fall back to NetShift's own directory when home
// is unknown.
func TestRunnerStartsInHomeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh; proc's Windows tests cover the working directory")
	}
	physical := func(path string) string {
		t.Helper()
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		return resolved
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	out, err := (proc.Exec{}).Run(t.Context(), "/bin/sh", []string{"-c", `pwd -P; printf '%s\n' "$PWD"`}, []string{"NETSHIFT_TEST=true"})
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err != nil || len(lines) != 2 || lines[0] != physical(home) || physical(lines[1]) != physical(home) {
		t.Fatalf("working directory and PWD: %q %v", out, err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, unknown := range []string{"", "relative/home"} {
		t.Setenv("HOME", unknown)
		out, err = (proc.Exec{}).Run(t.Context(), "/bin/sh", []string{"-c", "pwd -P"}, nil)
		if err != nil || strings.TrimSpace(string(out)) != physical(cwd) {
			t.Fatalf("HOME=%q: %q %v", unknown, out, err)
		}
	}
}
