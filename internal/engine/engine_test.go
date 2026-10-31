package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/store"
)

type fakeRunner struct {
	calls           [][]string
	rules           map[string]map[string]any
	failUpdate      map[string]int
	ambiguous       bool
	beforeUpdate    func()
	afterUpdate     func()
	beforeShow      func()
	commandFailures int
}

func (f *fakeRunner) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{program}, args...))
	if program != "az" {
		if f.commandFailures > 0 {
			f.commandFailures--
			return nil, errors.New("temporary failure")
		}
		return []byte(strings.Join(env, "\n")), nil
	}
	value := func(key string) string {
		for i, v := range args {
			if v == key && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	key := value("--nsg-name")
	if key == "" {
		key = value("--server-name")
	}
	r := f.rules[key]
	if r == nil {
		return nil, errors.New("not found")
	}
	if args[3] == "show" && f.beforeShow != nil {
		f.beforeShow()
	}
	if args[3] == "update" {
		if f.beforeUpdate != nil {
			f.beforeUpdate()
		}
		if f.failUpdate[key] > 0 && !f.ambiguous {
			f.failUpdate[key]--
			return nil, errors.New("transient Azure error")
		}
		if ip := value("--source-address-prefixes"); ip != "" {
			var sources []string
			for i, arg := range args {
				if arg == "--source-address-prefixes" {
					sources = append([]string{}, args[i+1:]...)
					break
				}
			}
			r["sourceAddressPrefix"] = ""
			r["sourceAddressPrefixes"] = sources
			if len(sources) == 1 {
				r["sourceAddressPrefix"] = sources[0]
				r["sourceAddressPrefixes"] = []string{}
			}
		} else {
			r["startIpAddress"] = value("--start-ip-address")
			r["endIpAddress"] = value("--end-ip-address")
		}
		if f.afterUpdate != nil {
			f.afterUpdate()
		}
		if f.failUpdate[key] > 0 {
			f.failUpdate[key]--
			return nil, context.DeadlineExceeded
		}
	}
	return json.Marshal(r)
}
func fixtureTarget(id, kind string) config.Target {
	t := config.Target{ID: id, Kind: kind, Subscription: "00000000-0000-0000-0000-000000000001", ResourceGroup: "test-group", Rule: "managed-ip", BootstrapIP: "8.8.8.8"}
	if kind == "nsg" {
		t.NSG = id
		t.Destination = "10.0.0.1/32"
		t.Ports = []string{"22", "443"}
		t.Priority = 1040
	} else {
		t.Server = id
	}
	return t
}
func fixtureRule(t config.Target, ip string) map[string]any {
	r := map[string]any{"id": expectedResourceID(t), "name": t.Rule}
	if t.Kind == "postgres" {
		r["startIpAddress"] = ip
		r["endIpAddress"] = ip
		return r
	}
	maps.Copy(r, map[string]any{"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "priority": t.Priority, "sourceAddressPrefix": ip + "/32", "sourceAddressPrefixes": []string{}, "sourcePortRange": "*", "destinationAddressPrefix": t.Destination, "destinationPortRanges": t.Ports, "description": "keep this exactly"})
	return r
}
func fixtureEngine(t *testing.T, targets ...config.Target) (*Engine, *fakeRunner, *time.Time) {
	t.Helper()
	a := config.ActionConfig{Type: "azure_allowlist", Targets: targets}
	c := config.Config{Version: 1, Profile: "test", Actions: map[string]config.ActionConfig{"allow": a}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	r := &fakeRunner{rules: map[string]map[string]any{}, failUpdate: map[string]int{}}
	for _, target := range targets {
		key := target.NSG
		if key == "" {
			key = target.Server
		}
		r.rules[key] = fixtureRule(target, target.BootstrapIP)
	}
	e := &Engine{Config: c, State: store.New(), Apply: true, Runner: r, Now: func() time.Time { return now }, Save: func(*store.State) error { return nil }, History: func(store.HistoryRecord) error { return nil }}
	return e, r, &now
}
func confirmed(ip string) discovery.Observation {
	return discovery.Observation{IP: ip, Online: true, Verified: true}
}
func updates(r *fakeRunner) int {
	n := 0
	for _, c := range r.calls {
		if len(c) > 4 && c[4] == "update" {
			n++
		}
	}
	return n
}
func TestDebounceNoAzureOnStableNetwork(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	ctx := context.Background()
	if err := e.step(ctx, confirmed("8.8.4.4"), false, false); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatal("acted before stable observation")
	}
	if err := e.step(ctx, confirmed("8.8.4.4"), false, false); err != nil {
		t.Fatal(err)
	}
	if updates(r) != 1 {
		t.Fatalf("updates=%d", updates(r))
	}
	calls := len(r.calls)
	for range 100 {
		if err := e.step(ctx, confirmed("8.8.4.4"), false, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.calls) != calls {
		t.Fatal("unchanged network triggered Azure calls")
	}
}
func TestPartialFailureRetriesOnlyIncompleteTarget(t *testing.T) {
	e, r, now := fixtureEngine(t, fixtureTarget("one", "nsg"), fixtureTarget("two", "postgres"))
	r.failUpdate["two"] = 1
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, false); err == nil {
		t.Fatal("expected partial failure")
	}
	if e.State.Action("allow").Target("one").AppliedIP != "8.8.4.4" {
		t.Fatal("successful receipt not retained")
	}
	calls := len(r.calls)
	*now = now.Add(10 * time.Second)
	_ = e.step(context.Background(), confirmed("8.8.4.4"), true, false)
	if len(r.calls) != calls {
		t.Fatal("retry ignored backoff")
	}
	*now = now.Add(30 * time.Second)
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, false); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.calls[calls:] {
		if strings.Contains(strings.Join(call, " "), "--nsg-name one") {
			t.Fatal("repeated successful target")
		}
	}
	if e.State.Action("allow").Pending != nil {
		t.Fatal("action not complete")
	}
}
func TestAmbiguousWriteAndRestartReconcileWithoutRepeatingWrite(t *testing.T) {
	e, r, now := fixtureEngine(t, fixtureTarget("one", "nsg"))
	r.failUpdate["one"] = 1
	r.ambiguous = true
	var saved []byte
	e.Save = func(s *store.State) error { saved, _ = json.Marshal(s); return nil }
	r.beforeUpdate = func() {
		var s store.State
		_ = json.Unmarshal(saved, &s)
		if s.Action("allow").Target("one").PendingIP != "8.8.4.4" {
			t.Fatal("cloud write preceded persisted intent")
		}
	}
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, false); err == nil {
		t.Fatal("expected timeout")
	}
	var restored store.State
	if err := json.Unmarshal(saved, &restored); err != nil {
		t.Fatal(err)
	}
	e.State = &restored
	*now = now.Add(time.Minute)
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, false); err != nil {
		t.Fatal(err)
	}
	if updates(r) != 1 {
		t.Fatal("ambiguous successful write was repeated")
	}
}
func TestDryRunNeverWritesStateOrCloud(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	e.Apply = false
	e.Save = func(*store.State) error { t.Fatal("dry run saved state"); return nil }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	if updates(r) != 0 {
		t.Fatal("dry run mutated Azure")
	}
}
func TestStateWriteFailurePreventsCloudMutation(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	e.Save = func(*store.State) error { return errors.New("disk full") }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil {
		t.Fatal("missing persistence error")
	}
	if len(r.calls) != 0 {
		t.Fatal("called Azure without durable intent")
	}
}
func TestOwnershipAndShapeGuards(t *testing.T) {
	cases := map[string]func(map[string]any){
		"shared-source":     func(r map[string]any) { r["sourceAddressPrefixes"] = []string{"8.8.8.8", "1.1.1.1"} },
		"broad-source":      func(r map[string]any) { r["sourceAddressPrefix"] = "8.8.8.0/24" },
		"unknown-owner":     func(r map[string]any) { r["sourceAddressPrefix"] = "1.1.1.1/32" },
		"wrong-port":        func(r map[string]any) { r["destinationPortRanges"] = []string{"22", "3389"} },
		"wrong-destination": func(r map[string]any) { r["destinationAddressPrefix"] = "*" },
		"wrong-priority":    func(r map[string]any) { r["priority"] = 100 },
		"wrong-rule":        func(r map[string]any) { r["id"] = "/subscriptions/elsewhere" },
		"outbound":          func(r map[string]any) { r["direction"] = "Outbound" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
			change(r.rules["one"])
			if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil {
				t.Fatal("unsafe update accepted")
			}
			if updates(r) != 0 {
				t.Fatal("mutated unsafe rule")
			}
		})
	}
	t.Run("postgres-range", func(t *testing.T) {
		e, r, _ := fixtureEngine(t, fixtureTarget("one", "postgres"))
		r.rules["one"]["endIpAddress"] = "8.8.8.9"
		if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil || updates(r) > 0 {
			t.Fatal("shared PG range changed")
		}
	})
}
func TestConnectivityEventsAndNoShellExpansion(t *testing.T) {
	c := config.Config{Version: 1, Profile: "events", Actions: map[string]config.ActionConfig{"hook": {Type: "command", On: []string{"ip_changed", "connectivity_lost", "connectivity_restored"}, Command: []string{"hook", "literal; $(touch /tmp/never)"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{}
	e := &Engine{Config: c, State: store.New(), Apply: true, Runner: r, Save: func(*store.State) error { return nil }, History: func(store.HistoryRecord) error { return nil }}
	_ = e.step(context.Background(), confirmed("8.8.8.8"), true, false)
	_ = e.step(context.Background(), discovery.Observation{Err: errors.New("offline")}, false, false)
	if len(r.calls) != 1 {
		t.Fatal("one failed observation fired offline event")
	}
	_ = e.step(context.Background(), discovery.Observation{Err: errors.New("offline")}, false, false)
	_ = e.step(context.Background(), discovery.Observation{Err: errors.New("offline")}, false, false)
	_ = e.step(context.Background(), confirmed("8.8.8.8"), false, false)
	if len(r.calls) != 3 {
		t.Fatalf("expected three edge events, got %d", len(r.calls))
	}
	if r.calls[0][1] != "literal; $(touch /tmp/never)" {
		t.Fatal("argv altered")
	}
}
func TestNewIPAndConfigEditInvalidatePendingWork(t *testing.T) {
	e, r, now := fixtureEngine(t, fixtureTarget("one", "nsg"))
	r.failUpdate["one"] = 1
	_ = e.step(context.Background(), confirmed("8.8.4.4"), true, false)
	*now = now.Add(time.Second)
	if err := e.step(context.Background(), confirmed("1.1.1.1"), true, false); err != nil {
		t.Fatal(err)
	}
	if got := e.State.Action("allow").AppliedIP; got != "1.1.1.1" {
		t.Fatal(got)
	}
	calls := len(r.calls)
	a := e.Config.Actions["allow"]
	a.TimeoutSeconds++
	e.Config.Actions["allow"] = a
	if err := e.step(context.Background(), confirmed("1.1.1.1"), true, false); err != nil {
		t.Fatal(err)
	}
	if e.State.Action("allow").AppliedFingerprint != config.Fingerprint(a) {
		t.Fatal("config not reconciled")
	}
	if len(r.calls) != calls {
		t.Fatal("unchanged target should reuse its current-IP receipt")
	}
}
func TestMissingRuleIsNotCreated(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	delete(r.rules, "one")
	err := e.step(context.Background(), confirmed("8.8.4.4"), true, true)
	if err == nil || updates(r) != 0 {
		t.Fatal(fmt.Sprint(err))
	}
}

func TestRecoveryRechecksAzureEvenWhenIPIsUnchanged(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	ctx := context.Background()
	if err := e.step(ctx, confirmed("8.8.8.8"), true, false); err != nil {
		t.Fatal(err)
	}
	calls := len(r.calls)
	_ = e.step(ctx, discovery.Observation{Err: errors.New("offline")}, false, false)
	_ = e.step(ctx, discovery.Observation{Err: errors.New("offline")}, false, false)
	if err := e.step(ctx, confirmed("8.8.8.8"), false, false); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != calls+1 || updates(r) != 0 {
		t.Fatal("recovery did not recheck the current rule")
	}
}

// The quiet poll's history check reads state without creating target
// entries, which would otherwise change state on a poll that did no work.
func TestHistoryMissingDoesNotCreateState(t *testing.T) {
	a := config.ActionConfig{Type: config.ActionAzure, Targets: []config.Target{fixtureTarget("one", "nsg"), fixtureTarget("db", "postgres")}}
	s := &store.ActionState{}
	if !historyMissing(a, s) {
		t.Fatal("missing baselines not reported")
	}
	if len(s.Targets) != 0 {
		t.Fatalf("check created target state: %v", s.Targets)
	}
	s.Targets = map[string]*store.TargetState{"one": {HistoryInitialized: true}, "db": {HistoryInitialized: true}}
	if historyMissing(a, s) {
		t.Fatal("initialized baselines reported missing")
	}
}
