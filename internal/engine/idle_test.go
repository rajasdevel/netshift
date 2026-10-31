package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
)

func TestQuietPollHasNoAllocations(t *testing.T) {
	for _, kind := range []string{"command", "azure"} {
		t.Run(kind, func(t *testing.T) {
			e, r, _ := featureEngine(t)
			if kind == "azure" {
				targets := make([]config.Target, 19)
				for i := range targets {
					targets[i] = fixtureTarget(fmt.Sprintf("target-%d", i), "nsg")
				}
				e, r, _ = fixtureEngine(t, targets...)
			}
			ctx := t.Context()
			o := confirmed("8.8.8.8")
			if err := e.step(ctx, o, acceptAtOnce, reapplyStale); err != nil {
				t.Fatal(err)
			}
			e.cachedNames = config.ActionNames(e.Config)
			e.cachedActions = map[string]string{}
			for _, name := range e.cachedNames {
				e.cachedActions[name] = config.Fingerprint(e.Config.Actions[name])
			}
			calls := len(r.calls)
			e.Save = func(*store.State) error { t.Fatal("quiet poll wrote state"); return nil }
			allocations := testing.AllocsPerRun(1000, func() {
				if err := e.step(ctx, o, acceptConfirmed, reapplyStale); err != nil {
					t.Fatal(err)
				}
			})
			if allocations != 0 || len(r.calls) != calls {
				t.Fatalf("allocations=%v, helper calls=%d", allocations, len(r.calls)-calls)
			}
		})
	}
}

// Compare skipped idle checkpoints with the full checkpoint path over changes,
// failures, backoff, notifications, local events, and process restarts.
func TestSkippedCheckpointsPreserveStateTransitions(t *testing.T) {
	fast, fastRunner, fastNow := featureEngine(t)
	full, fullRunner, fullNow := featureEngine(t)
	engines := []*Engine{fast, full}
	runners := []*fakeRunner{fastRunner, fullRunner}
	clocks := []*time.Time{fastNow, fullNow}
	saved := [2][]byte{}
	writes := [2]int{}
	notices := [2]int{}
	checkFails := false
	for i, e := range engines {
		a := e.Config.Actions["hook"]
		a.On = []string{"ip_changed", "connectivity_lost", "connectivity_restored", "monitor_resumed"}
		a.Checks = []config.CheckConfig{{Name: "ready", Type: "tcp", Address: "127.0.0.1:9", TimeoutSeconds: 1}}
		e.Config.Actions["hook"] = a
		e.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 1, CooldownSeconds: 30}
		e.Save = func(s *store.State) error { saved[i], _ = json.Marshal(s); writes[i]++; return nil }
		e.Notify = func(context.Context, string, string) error { notices[i]++; return nil }
		e.Check = func(context.Context, config.CheckConfig) error {
			if checkFails {
				return errors.New("not ready")
			}
			return nil
		}
	}
	observations := []discovery.Observation{
		confirmed("8.8.8.8"), confirmed("8.8.8.8"), confirmed("8.8.8.8"),
		confirmed("1.1.1.1"), confirmed("8.8.8.8"), confirmed("1.1.1.1"), confirmed("1.1.1.1"),
		{Err: errors.New("unavailable")}, {Err: errors.New("unavailable")}, {Err: errors.New("unavailable")},
		{Online: true, Err: errors.New("unconfirmed")}, confirmed("1.1.1.1"), confirmed("1.1.1.1"),
	}
	for tick := range 130 {
		checkFails = tick%17 < 4
		for i, e := range engines {
			*clocks[i] = clocks[i].Add(10 * time.Second)
			if tick%23 == 0 {
				runners[i].commandFailures = 1
			}
			if tick%19 == 0 {
				// No action subscribes: the event itself must still persist.
				e.emit(store.Event{Type: "interface_changed", Source: "interfaces", Value: fmt.Sprint(tick), At: e.now()})
			}
			if tick%29 == 0 {
				e.emit(store.Event{Type: "monitor_resumed", Source: "watch_timer", Value: "300", At: e.now()})
			}
			if tick%31 == 0 {
				a := e.Config.Actions["hook"]
				a.Command = []string{"hook", fmt.Sprint(tick)}
				e.Config.Actions["hook"] = a
			}
		}
		full.pendingSave = true // Force a full fingerprint checkpoint on every step.
		fastErr := fast.step(t.Context(), observations[tick%len(observations)], acceptConfirmed, reapplyStale)
		fullErr := full.step(t.Context(), observations[tick%len(observations)], acceptConfirmed, reapplyStale)
		if fmt.Sprint(fastErr) != fmt.Sprint(fullErr) || !reflect.DeepEqual(fast.State, full.State) || !bytes.Equal(saved[0], saved[1]) || writes[0] != writes[1] || notices[0] != notices[1] || !reflect.DeepEqual(fastRunner.calls, fullRunner.calls) {
			t.Fatalf("transition diverged at tick %d: %v / %v", tick, fastErr, fullErr)
		}
		current, _ := json.Marshal(fast.State)
		if !bytes.Equal(current, saved[0]) {
			t.Fatalf("state not durable at tick %d", tick)
		}
		if tick%11 == 10 {
			for i, e := range engines {
				var restored store.State
				if err := json.Unmarshal(saved[i], &restored); err != nil {
					t.Fatal(err)
				}
				e.State = &restored
				e.savedFingerprint = config.Fingerprint(e.State)
				e.pendingSave = false
			}
		}
	}
}

func TestFailedCheckpointRetriesBeforeAction(t *testing.T) {
	e, r, _ := featureEngine(t)
	o := confirmed("8.8.8.8")
	if err := e.step(t.Context(), o, acceptAtOnce, reapplyStale); err != nil {
		t.Fatal(err)
	}
	calls := len(r.calls)
	diskFull := true
	e.Save = func(*store.State) error {
		if diskFull {
			return errors.New("disk full")
		}
		return nil
	}
	e.queue("hook", store.Event{Type: "ip_changed", IP: o.IP, At: e.now()})
	for range 2 {
		if err := e.step(t.Context(), o, acceptConfirmed, reapplyStale); err == nil {
			t.Fatal("failed checkpoint skipped")
		}
		if len(r.calls) != calls {
			t.Fatal("action ran before pending state was durable")
		}
	}
	diskFull = false
	if err := e.step(t.Context(), o, acceptConfirmed, reapplyStale); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != calls+1 || e.pendingSave {
		t.Fatal("pending action/save did not recover")
	}
	// An explicit save remains authoritative even for mutations outside step.
	e.State.Action("hook").Retired = true
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	if e.savedFingerprint != config.Fingerprint(e.State) {
		t.Fatal("explicit save skipped a mutation")
	}
}

func TestUnsubscribedLocalEventPersistsOnQuietPoll(t *testing.T) {
	e, _, _ := featureEngine(t)
	o := confirmed("8.8.8.8")
	if err := e.step(t.Context(), o, acceptAtOnce, reapplyStale); err != nil {
		t.Fatal(err)
	}
	writes := 0
	e.Save = func(s *store.State) error {
		writes++
		if s.LastEvent.Type != "interface_changed" {
			t.Fatal("event missing")
		}
		return nil
	}
	e.emit(store.Event{Type: "interface_changed", Source: "interfaces", Value: "changed", At: e.now()})
	if err := e.step(t.Context(), o, acceptConfirmed, reapplyStale); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("event checkpoints=%d", writes)
	}
	if err := e.step(t.Context(), o, acceptConfirmed, reapplyStale); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal("quiet poll repeated event checkpoint")
	}
}

type observerFunc func(context.Context, string) discovery.Observation

func (f observerFunc) Observe(ctx context.Context, ip string) discovery.Observation {
	return f(ctx, ip)
}

func TestWatchTimerWaitsAfterWorkAndCancels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, runner, _ := featureEngine(t)
		e.Now = nil
		e.Config.Monitor.IntervalSeconds = 30
		e.Config.Monitor.ResumeAfterSeconds = 60
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		var finished time.Time
		e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
			result, err := runner.Run(ctx, program, args, env)
			time.Sleep(65 * time.Second) // Longer than both poll and resume thresholds.
			finished = time.Now()
			return result, err
		})
		calls := 0
		e.Observer = observerFunc(func(context.Context, string) discovery.Observation {
			if !finished.IsZero() && time.Since(finished) != 30*time.Second {
				t.Fatal("timer fired early, late, or caught up after work")
			}
			calls++
			if calls == 3 {
				cancel()
				return confirmed("8.8.8.8")
			}
			time.Sleep(45 * time.Second) // Expire the initial timer before its Reset.
			finished = time.Now()
			return confirmed("8.8.8.8")
		})
		if err := e.Watch(ctx); err != nil {
			t.Fatal(err)
		}
		if calls != 3 {
			t.Fatalf("observations=%d", calls)
		}
		if e.State.LastEvent != nil && e.State.LastEvent.Type == "monitor_resumed" {
			t.Fatal("long observation/action work emitted a resume event")
		}
	})
}

func TestWatchCancellationDuringWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, _ := featureEngine(t)
		e.Config.Monitor.IntervalSeconds = 30
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		e.Observer = observerFunc(func(context.Context, string) discovery.Observation {
			calls++
			time.AfterFunc(time.Second, cancel)
			return confirmed("8.8.8.8")
		})
		started := time.Now()
		if err := e.Watch(ctx); err != nil {
			t.Fatal(err)
		}
		if calls != 1 || time.Since(started) != time.Second {
			t.Fatal("shutdown waited for the poll interval")
		}
	})
}

func BenchmarkQuietWatch(b *testing.B) {
	e, _, _ := featureEngine(b)
	e.Config.Monitor.IntervalSeconds = 0 // Exercise timer turnover without wall-clock waits.
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()
	if err := e.step(ctx, confirmed("8.8.8.8"), acceptAtOnce, reapplyStale); err != nil {
		b.Fatal(err)
	}
	// Each poll is one iteration; watch's own startup happens before the first
	// b.Loop call, so it is not measured.
	e.Observer = observerFunc(func(context.Context, string) discovery.Observation {
		if !b.Loop() {
			cancel()
		}
		return confirmed("8.8.8.8")
	})
	b.ReportAllocs()
	if err := e.Watch(ctx); err != nil {
		b.Fatal(err)
	}
}

// needsReconcile must agree with this reference expression over every
// combination of the inputs it reads.
func TestNeedsReconcileTruthTable(t *testing.T) {
	e, _, now := featureEngine(t)
	const ip = "8.8.8.8"
	reference := func(name string, a config.ActionConfig, as *store.ActionState, force bool) bool {
		periodic := a.Devices != nil && now.Sub(as.LastSuccess) >= time.Duration(a.Devices.ReconcileSeconds)*time.Second
		return a.Type == "azure_allowlist" && (force || periodic && as.Pending == nil || ((as.AppliedFingerprint != e.actionFingerprint(name) || as.AppliedIP != ip || historyMissing(a, as)) && as.Pending == nil) || (as.Pending != nil && as.Pending.IP != ip))
	}
	compared := 0
	for _, kind := range []string{"command", "azure_allowlist"} {
		for _, devices := range []*config.DevicesConfig{nil, {ReconcileSeconds: 60}} {
			a := config.ActionConfig{Type: kind, Devices: devices, Targets: []config.Target{fixtureTarget("one", "nsg")}}
			e.Config.Actions["act"] = a
			for _, lastSuccess := range []time.Duration{0, 59 * time.Second, 60 * time.Second} {
				for _, pending := range []*store.Event{nil, {IP: ip}, {IP: "1.1.1.1"}} {
					for _, fingerprint := range []string{e.actionFingerprint("act"), "old"} {
						for _, applied := range []string{ip, "1.1.1.1"} {
							for _, history := range []bool{true, false} {
								for _, force := range []bool{false, true} {
									state := func() *store.ActionState {
										return &store.ActionState{Pending: pending, AppliedFingerprint: fingerprint, AppliedIP: applied, LastSuccess: now.Add(-lastSuccess),
											Targets: map[string]*store.TargetState{"one": {HistoryInitialized: history}}}
									}
									want := reference("act", a, state(), force)
									if got := e.needsReconcile("act", &a, state(), ip, *now, force); got != want {
										t.Fatalf("%s devices=%v since=%v pending=%v fingerprint=%s applied=%s history=%v force=%v: got %v, want %v",
											kind, devices != nil, lastSuccess, pending, fingerprint, applied, history, force, got, want)
									}
									compared++
								}
							}
						}
					}
				}
			}
		}
	}
	if compared != 576 {
		t.Fatal(compared)
	}
}

func TestNeedsReconcile(t *testing.T) {
	e, _, now := featureEngine(t)
	const ip = "8.8.8.8"
	e.Config.Actions["azure"] = config.ActionConfig{Type: "azure_allowlist", Targets: []config.Target{fixtureTarget("one", "nsg")}}
	e.Config.Actions["devices"] = config.ActionConfig{Type: "azure_allowlist", Devices: &config.DevicesConfig{ReconcileSeconds: 60}, Targets: []config.Target{fixtureTarget("one", "nsg")}}
	for _, test := range []struct {
		name, action string
		force        bool
		elapsed      time.Duration
		edit         func(*store.ActionState)
		want         bool
	}{
		{name: "up to date", action: "azure"},
		{name: "command actions never reconcile", action: "hook", force: true},
		{name: "forced", action: "azure", force: true, want: true},
		{name: "configuration changed", action: "azure", edit: func(s *store.ActionState) { s.AppliedFingerprint = "old" }, want: true},
		{name: "address changed", action: "azure", edit: func(s *store.ActionState) { s.AppliedIP = "1.1.1.1" }, want: true},
		{name: "history baseline missing", action: "azure", edit: func(s *store.ActionState) { s.Targets["one"].HistoryInitialized = false }, want: true},
		{name: "target never seen", action: "azure", edit: func(s *store.ActionState) { delete(s.Targets, "one") }, want: true},
		{name: "pending for this address", action: "azure", edit: func(s *store.ActionState) { s.Pending = &store.Event{IP: ip}; s.AppliedIP = "" }},
		{name: "pending for an older address", action: "azure", edit: func(s *store.ActionState) { s.Pending = &store.Event{IP: "1.1.1.1"} }, want: true},
		{name: "device reconciliation due", action: "devices", elapsed: time.Minute, want: true},
		{name: "device reconciliation not due", action: "devices", elapsed: 59 * time.Second},
		{name: "device reconciliation waits for pending", action: "devices", elapsed: time.Hour, edit: func(s *store.ActionState) { s.Pending = &store.Event{IP: ip} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &store.ActionState{AppliedIP: ip, AppliedFingerprint: e.actionFingerprint(test.action), LastSuccess: *now,
				Targets: map[string]*store.TargetState{"one": {HistoryInitialized: true}}}
			if test.edit != nil {
				test.edit(s)
			}
			a := e.Config.Actions[test.action]
			if got := e.needsReconcile(test.action, &a, s, ip, now.Add(test.elapsed), test.force); got != test.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func TestRetryDelayDoublesUpToTheCap(t *testing.T) {
	for _, test := range []struct {
		retry, max, failures int
		want                 time.Duration
	}{
		{30, 900, 1, 30 * time.Second},
		{30, 900, 2, time.Minute},
		{30, 900, 5, 8 * time.Minute},
		{30, 900, 6, 15 * time.Minute},
		{30, 900, 1000, 15 * time.Minute},
		{30, 100, 3, 100 * time.Second},
		{60, 60, 4, time.Minute},
	} {
		m := config.MonitorConfig{RetrySeconds: test.retry, MaxRetrySeconds: test.max}
		if got := retryDelay(m, test.failures); got != test.want {
			t.Errorf("retry=%d max=%d failures=%d: got %v, want %v", test.retry, test.max, test.failures, got, test.want)
		}
	}
}

// Every way a stop request ends watch logs monitor_stopped exactly once, and
// a stop that interrupts an action is not an incomplete cycle.
func TestWatchLogsEachStopOnce(t *testing.T) {
	for _, stop := range []string{"during observation", "during an action", "while waiting"} {
		t.Run(stop, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e, _, _ := featureEngine(t)
				e.Now = nil
				var logged bytes.Buffer
				e.Log = eventlog.Logger{Out: &logged}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				e.Observer = observerFunc(func(context.Context, string) discovery.Observation {
					switch stop {
					case "during observation":
						cancel()
						return discovery.Observation{Err: context.Canceled}
					case "while waiting":
						time.AfterFunc(time.Second, cancel)
					}
					return confirmed("8.8.8.8")
				})
				e.Runner = runnerFunc(func(ctx context.Context, _ string, _, _ []string) ([]byte, error) {
					if stop == "during an action" {
						cancel()
						return nil, ctx.Err()
					}
					return nil, nil
				})
				// The first poll confirms 8.8.8.8 only after two observations,
				// so make it the known address and queue the hook directly.
				e.State.IP, e.State.Connectivity = "8.8.8.8", "online"
				e.queue("hook", store.Event{Type: "ip_changed", IP: "8.8.8.8", At: time.Now()})
				if err := e.Watch(ctx); err != nil {
					t.Fatal(err)
				}
				log := logged.String()
				if n := strings.Count(log, `"event":"monitor_stopped"`); n != 1 || strings.Contains(log, "cycle_incomplete") {
					t.Fatalf("monitor_stopped=%d log:\n%s", n, log)
				}
				if stop == "during an action" && e.State.Action("hook").Pending == nil {
					t.Fatal("interrupted action not left pending")
				}
			})
		})
	}
}
