package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
)

// deviceCloud is a fake Azure CLI with ARM semantics: resource and tag names
// are case-insensitive, and NSG and PostgreSQL rule create is an upsert (PUT)
// that replaces a rule whose name differs only in case. Writes are counted by
// "kind:verb:parent:name" keys; failAfter makes one write land and then time
// out (ambiguous), and reject makes one write fail without landing.
type deviceCloud struct {
	nsgs       map[string]*azureNSG
	pg         map[string]map[string]azureRule
	writes     map[string]int
	calls      int
	failAfter  string
	reject     string
	afterWrite func(string)
}

func argValues(args []string, key string) []string {
	for i, v := range args {
		if v == key {
			out := []string{}
			for _, s := range args[i+1:] {
				if strings.HasPrefix(s, "--") {
					break
				}
				out = append(out, s)
			}
			return out
		}
	}
	return nil
}

// rejected fails a write definitively, before it changes anything.
func (f *deviceCloud) rejected(key string) error {
	if f.reject != "" && f.reject == key {
		f.reject = ""
		return errors.New("Azure rejected the request: " + key)
	}
	return nil
}
func (f *deviceCloud) wrote(key string) error {
	f.writes[key]++
	if f.afterWrite != nil {
		f.afterWrite(key)
	}
	if f.failAfter == key {
		f.failAfter = ""
		return context.DeadlineExceeded
	}
	return nil
}

// foldKey returns the stored spelling of name among keys, ignoring case.
func foldKey[V any](m map[string]V, name string) (string, bool) {
	for k := range m {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}
	return name, false
}
func (f *deviceCloud) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.calls++
	sub, group := argValue(args, "--subscription"), argValue(args, "--resource-group")
	if args[0] == "tag" {
		n := f.nsgs[strings.ToLower(argValue(args, "--resource-id"))]
		if n == nil {
			return nil, errors.New("missing NSG")
		}
		name, value, ok := strings.Cut(argValue(args, "--tags"), "=")
		if !ok {
			return nil, errors.New("invalid tag")
		}
		if err := f.rejected("tag:" + name); err != nil {
			return nil, err
		}
		key, found := foldKey(n.Tags, name)
		if argValue(args, "--operation") == "Delete" {
			if found && n.Tags[key] == value {
				delete(n.Tags, key)
			}
		} else {
			n.Tags[key] = value
		}
		if err := f.wrote("tag:" + name); err != nil {
			return nil, err
		}
		return json.Marshal(n)
	}
	if args[0] == "network" {
		name := argValue(args, "--nsg-name")
		if name == "" {
			name = argValue(args, "--name")
		}
		n := f.nsgs[strings.ToLower(config.NSGResourceID(config.Target{Subscription: sub, ResourceGroup: group, NSG: name}))]
		if n == nil {
			return nil, errors.New("missing NSG")
		}
		if args[2] == "show" {
			return json.Marshal(n)
		}
		verb := args[3]
		rule := argValue(args, "--name")
		index := slices.IndexFunc(n.Rules, func(r azureRule) bool { return strings.EqualFold(r.Name, rule) })
		if verb == "show" {
			if index < 0 {
				return nil, errors.New("missing rule")
			}
			return json.Marshal(n.Rules[index])
		}
		key := "nsg:" + verb + ":" + name + ":" + rule
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		target := config.Target{Kind: config.KindNSG, Subscription: sub, ResourceGroup: group, NSG: name, Rule: rule}
		if verb == "create" {
			var priority int
			fmt.Sscan(argValue(args, "--priority"), &priority)
			r := azureRule{ID: expectedResourceID(target), Name: rule, Access: argValue(args, "--access"), Direction: argValue(args, "--direction"), Protocol: argValue(args, "--protocol"), Priority: priority, Sources: argValues(args, "--source-address-prefixes"), SourcePorts: argValues(args, "--source-port-ranges"), Destinations: argValues(args, "--destination-address-prefixes"), Ports: argValues(args, "--destination-port-ranges"), Description: argValue(args, "--description")}
			if index >= 0 {
				// PUT replaces the existing rule, keeping its stored name.
				r.Name, r.ID = n.Rules[index].Name, n.Rules[index].ID
				n.Rules[index] = r
			} else {
				n.Rules = append(n.Rules, r)
			}
		} else if index < 0 {
			return nil, errors.New("missing rule")
		} else if verb == "delete" {
			n.Rules = append(n.Rules[:index], n.Rules[index+1:]...)
		} else if verb == "update" {
			n.Rules[index].Source = ""
			n.Rules[index].Sources = argValues(args, "--source-address-prefixes")
		} else {
			return nil, errors.New("unexpected NSG verb")
		}
		return []byte(`{}`), f.wrote(key)
	}
	if args[0] == "postgres" {
		server := argValue(args, "--server-name")
		rules := f.pg[server]
		if rules == nil {
			return nil, errors.New("missing server")
		}
		verb := args[3]
		name := argValue(args, "--name")
		stored, found := foldKey(rules, name)
		r := rules[stored]
		if verb == "list" {
			rows := []azureRule{}
			for _, r := range rules {
				rows = append(rows, r)
			}
			return json.Marshal(rows)
		}
		if verb == "show" {
			if !found {
				return nil, errors.New("missing PG rule")
			}
			return json.Marshal(r)
		}
		key := "pg:" + verb + ":" + server + ":" + name
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		if verb == "create" && !found {
			r = azureRule{ID: expectedResourceID(config.Target{Kind: config.KindPostgres, Subscription: sub, ResourceGroup: group, Server: server, Rule: name}), Name: name}
		}
		if verb == "delete" {
			if !found {
				return nil, errors.New("missing PG rule")
			}
			delete(rules, stored)
		} else if verb == "create" || verb == "update" {
			// Create is a PUT: an existing rule is overwritten in place.
			if verb == "update" && !found {
				return nil, errors.New("missing PG rule")
			}
			r.StartIP = argValue(args, "--start-ip-address")
			r.EndIP = argValue(args, "--end-ip-address")
			rules[stored] = r
		} else {
			return nil, errors.New("unexpected PG verb")
		}
		if err := f.wrote(key); err != nil {
			return nil, err
		}
		return json.Marshal(r)
	}
	return nil, fmt.Errorf("unexpected command %v", args)
}
func deviceFixture(t *testing.T) (*Engine, *deviceCloud) {
	t.Helper()
	f := &deviceCloud{nsgs: map[string]*azureNSG{}, pg: map[string]map[string]azureRule{}, writes: map[string]int{}}
	targets := []config.Target{}
	for _, name := range []string{"one", "two"} {
		target := fixtureTarget(name, "nsg")
		raw, _ := json.Marshal(fixtureRule(target, "8.8.8.8"))
		var r azureRule
		json.Unmarshal(raw, &r)
		r.Source = ""
		r.Sources = []string{"8.8.8.8/32", "9.9.9.9"}
		n := &azureNSG{Name: name, ID: config.NSGResourceID(target), ResourceGroup: target.ResourceGroup, Tags: map[string]string{"comment": "human comment", "netshift.test.ip-history": `{"v":1,"ips":["8.8.8.8"]}`}, Rules: []azureRule{r}}
		f.nsgs[strings.ToLower(n.ID)] = n
		target.Template = captureTemplate(r)
		target.SourceMode = "replace_known"
		target.RuleShape = ruleShape(r)
		target.KnownIPs = []string{"8.8.8.8"}
		target.BootstrapIP = ""
		target.Priority = 0
		target.Ports = nil
		target.Destination = ""
		targets = append(targets, target)
	}
	pg := fixtureTarget("database", "postgres")
	raw, _ := json.Marshal(fixtureRule(pg, "8.8.8.8"))
	var r azureRule
	json.Unmarshal(raw, &r)
	f.pg[pg.Server] = map[string]azureRule{pg.Rule: r}
	other := pg
	other.Rule = "unrelated-user"
	raw, _ = json.Marshal(fixtureRule(other, "4.4.4.4"))
	json.Unmarshal(raw, &r)
	f.pg[pg.Server][other.Rule] = r
	targets = append(targets, pg)
	c := config.Config{Version: 1, Profile: "test", Identity: "sam@laptop", KnownIPs: []string{"8.8.8.8"}, Actions: map[string]config.ActionConfig{"allow": {Type: "azure_allowlist", Devices: &config.DevicesConfig{TagPrefix: "netshift.test.device.", HistoryLimit: 10, LegacyTag: "netshift.test.ip-history", LegacyIdentity: "sam@laptop"}, Targets: targets}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e := deviceEngine(t, c, f, c.Identity)
	return e, f
}
func deviceEngine(t *testing.T, c config.Config, f *deviceCloud, id string) *Engine {
	t.Helper()
	raw, _ := json.Marshal(c)
	json.Unmarshal(raw, &c)
	c.Identity = id
	state := store.New()
	if err := BindIdentity(c, state); err != nil {
		t.Fatal(err)
	}
	return &Engine{Config: c, State: state, StatePath: filepath.Join(t.TempDir(), "state.json"), Apply: true, Runner: f}
}
func driveDevice(t *testing.T, e *Engine, ip string) {
	t.Helper()
	e.State.IP = ip
	if err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], ip, false); err != nil {
		t.Fatal(err)
	}
}
func assertDeviceIPs(t *testing.T, e *Engine, f *deviceCloud, ips ...string) {
	t.Helper()
	for _, n := range f.nsgs {
		for _, r := range n.Rules {
			got := []string{}
			for _, s := range r.sourceList() {
				ip, err := singleIP(s)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, ip)
			}
			if !sameStrings(got, ips) {
				t.Fatalf("%s got %v want %v", n.Name, got, ips)
			}
			if r.Description != "keep this exactly" {
				t.Fatal("comment changed")
			}
		}
		if n.Tags["comment"] != "human comment" {
			t.Fatal("human tag changed")
		}
	}
}
func TestDeviceIdentityAndStableNames(t *testing.T) {
	id, err := config.CanonicalIdentity("sam@Laptop.local")
	if err != nil || id != "sam@laptop" {
		t.Fatal(id, err)
	}
	e, _ := deviceFixture(t)
	target := e.Config.Actions["allow"].Targets[2]
	names := map[string]bool{}
	for _, id := range []string{"sam@laptop", "sam@desktop", "lee@laptop", "Sam@laptop", "sam-a@desktop", "sam.a@desktop"} {
		name := devicePGTarget(e.Config, target, id).Rule
		if names[name] || len(name) > 128 {
			t.Fatal(name)
		}
		names[name] = true
	}
	if !strings.Contains(devicePGTarget(e.Config, target, "sam@desktop").Rule, "sam-desktop") {
		t.Fatal("unreadable name")
	}
	s := store.New()
	s.Identity = "sam@desktop"
	if BindIdentity(e.Config, s) == nil {
		t.Fatal("adopted another host's state")
	}
}
func TestDevicesTwoMachinesAndTwoUsersDoNotConflict(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "1.1.1.1")
	other := deviceEngine(t, e.Config, f, "lee@laptop")
	driveDevice(t, other, "4.2.2.2")
	beforeOther := f.pg["database"][devicePGTarget(other.Config, other.Config.Actions["allow"].Targets[2], other.Config.Identity).Rule]
	driveDevice(t, e, "208.67.222.222")
	assertDeviceIPs(t, e, f, "9.9.9.9", "1.1.1.1", "4.2.2.2", "208.67.222.222")
	if !samePGRule(f.pg["database"][beforeOther.Name], beforeOther) {
		t.Fatal("another user PG rule changed")
	}
}
func TestDeviceSharedNATAndCreateOnce(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "8.8.4.4")
	driveDevice(t, e, "1.1.1.1")
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4", "1.1.1.1")
	driveDevice(t, e, "208.67.222.222")
	driveDevice(t, home, "4.2.2.2")
	assertDeviceIPs(t, e, f, "9.9.9.9", "208.67.222.222", "4.2.2.2")
	for _, id := range []string{"sam@laptop", "sam@desktop"} {
		rule := devicePGTarget(e.Config, e.Config.Actions["allow"].Targets[2], id).Rule
		if f.writes["pg:create:database:"+rule] != 1 {
			t.Fatalf("rule recreated: %v", f.writes)
		}
	}
	if _, ok := f.pg["database"]["managed-ip"]; ok {
		t.Fatal("legacy PG rule remains")
	}
	if f.pg["database"]["unrelated-user"].StartIP != "4.4.4.4" {
		t.Fatal("changed other user")
	}
}
func TestRetirementIsExplicitAndTombstoneBlocksOldWriter(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "1.1.1.1")
	a := e.Config.Actions["allow"]
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	home.State.IP = "4.2.2.2"
	if err := home.runDevices(context.Background(), "allow", a, "4.2.2.2", false); !errors.Is(err, errIdentityRetired) {
		t.Fatal(err)
	}
	if !home.State.Action("allow").Retired {
		t.Fatal("sleeping machine ignored retirement")
	}
	reg, err := e.loadDevices(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Devices["sam@desktop"].Retired {
		t.Fatal("marker removed")
	}
	stale := DeviceRecord{Version: 2, Identity: "sam@desktop", IPs: []string{"1.1.1.1"}, Revision: 999}
	if err = reg.merge(stale); err != nil {
		t.Fatal(err)
	}
	if !reg.Devices["sam@desktop"].Retired {
		t.Fatal("stale writer resurrected owner")
	}
	raw, _ := encodeDevice(stale, 10)
	if e.writeDeviceTag(context.Background(), "allow", a, config.NSGGroups(a)[0], tagWrite{key: deviceTag(a, "sam@desktop", false), value: raw, owner: "sam@desktop"}) == nil {
		t.Fatal("stale tag write allowed")
	}
	if e.retireDevice(context.Background(), "allow", a, "lee@desktop") == nil {
		t.Fatal("retired another username")
	}
}
func TestLastRetirementAndExplicitRestoration(t *testing.T) {
	e, f := deviceFixture(t)
	for _, n := range f.nsgs {
		n.Rules[0].Sources = []string{"8.8.8.8/32"}
	}
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		if len(n.Rules) != 0 {
			t.Fatal("last-owner rule remained")
		}
	}
	// The watcher observes the marker and cannot restore rules.
	if err := e.runDevices(context.Background(), "allow", a, "1.1.1.1", false); !errors.Is(err, errIdentityRetired) {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		if len(n.Rules) != 0 {
			t.Fatal("watch resurrected a rule")
		}
	}
	if err := e.activateDevice(context.Background(), "allow", a); err != nil {
		t.Fatal(err)
	}
	if err := e.runDevices(context.Background(), "allow", a, "1.1.1.1", true); err != nil {
		t.Fatal(err)
	}
	assertDeviceIPs(t, e, f, "1.1.1.1")
	for _, n := range f.nsgs {
		if len(n.Rules) != 1 {
			t.Fatal("template not restored")
		}
	}
}
func TestDeviceHistoryBoundsAndConflicts(t *testing.T) {
	reg := newRegistry()
	old := DeviceRecord{Version: 2, Identity: "sam@desktop", IPs: []string{"8.8.8.8"}, Revision: 1}
	if err := reg.merge(old); err != nil {
		t.Fatal(err)
	}
	conflict := old
	conflict.IPs = []string{"1.1.1.1"}
	if reg.merge(conflict) == nil {
		t.Fatal("same revision conflict ignored")
	}
	ips := []string{}
	for i := 1; i <= 20; i++ {
		ips = append(ips, fmt.Sprintf("8.8.4.%d", i))
	}
	raw, err := encodeDevice(DeviceRecord{Version: 2, Identity: "sam@laptop", IPs: ips, Revision: 10}, 10)
	if err != nil || len(raw) > 256 {
		t.Fatal(raw, err)
	}
	d, err := parseDevice(raw)
	if err != nil || len(d.IPs) != 10 {
		t.Fatal(d, err)
	}
	long := strings.Repeat("u", 32) + "@" + strings.Repeat("h", 45)
	raw, err = encodeDevice(DeviceRecord{Version: 2, Identity: long, IPs: ips, Revision: 10}, 10)
	if err != nil {
		t.Fatal(err)
	}
	d, _ = parseDevice(raw)
	if len(d.IPs) < 5 || len(d.IPs) > 10 {
		t.Fatal(d)
	}
	if _, err = parseDevice(raw + ` {}`); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
func TestDeviceDryRunAndUnownedPGGuard(t *testing.T) {
	e, f := deviceFixture(t)
	e.Apply = false
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal("dry run wrote", f.writes)
	}
	e.Apply = true
	own := devicePGTarget(e.Config, e.Config.Actions["allow"].Targets[2], e.Config.Identity)
	raw, _ := json.Marshal(fixtureRule(own, "1.0.0.1"))
	var r azureRule
	json.Unmarshal(raw, &r)
	f.pg[own.Server][own.Rule] = r
	if err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false); err == nil {
		t.Fatal("adopted unknown identity-name collision")
	}
	if len(f.writes) != 0 {
		t.Fatal("preflight mutated before rejecting unknown PG ownership")
	}
}
func TestDeviceInterruptedMetadataRecovers(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	f.failAfter = "tag:" + deviceTag(a, e.Config.Identity, false)
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("expected interrupted response")
	}
	pending := false
	for _, s := range e.State.Action("allow").SharedHistory {
		pending = pending || s.Pending != nil
	}
	if !pending {
		t.Fatal("missing durable intent")
	}
	driveDevice(t, e, e.State.IP)
	for _, s := range e.State.Action("allow").SharedHistory {
		if s.Pending != nil {
			t.Fatal("intent not reconciled")
		}
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
}
func TestDevicePeriodicReconcileAndQuietIdle(t *testing.T) {
	e, f := deviceFixture(t)
	now := time.Now()
	e.Now = func() time.Time { return now }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	calls := f.calls
	now = now.Add(time.Minute)
	if err := e.step(context.Background(), confirmed("8.8.4.4"), false, false); err != nil {
		t.Fatal(err)
	}
	if f.calls != calls {
		t.Fatal("stable poll contacted Azure")
	}
	now = now.Add(30 * time.Minute)
	if err := e.step(context.Background(), confirmed("8.8.4.4"), false, false); err != nil {
		t.Fatal(err)
	}
	if f.calls == calls {
		t.Fatal("periodic reconciliation absent")
	}
}
func TestDeviceConcurrentEnrollmentConverges(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	added := false
	f.afterWrite = func(key string) {
		if !added && strings.HasPrefix(key, "nsg:update:") {
			added = true
			d := DeviceRecord{Version: 2, Identity: "sam@desktop", IPs: []string{"1.1.1.1"}, Revision: 1}
			raw, _ := encodeDevice(d, 10)
			for _, n := range f.nsgs {
				n.Tags[deviceTag(a, d.Identity, false)] = raw
			}
		}
	}
	driveDevice(t, e, "4.2.2.2")
	if !added {
		t.Fatal("test did not interleave")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "4.2.2.2", "1.1.1.1")
}
func TestDeviceMigrationOwnerOnlyAndOldClientsFailClosed(t *testing.T) {
	e, f := deviceFixture(t)
	other := deviceEngine(t, e.Config, f, "lee@laptop")
	other.State.IP = "4.2.2.2"
	if other.runDevices(context.Background(), "allow", other.Config.Actions["allow"], other.State.IP, false) == nil {
		t.Fatal("other user adopted legacy history")
	}
	if len(f.writes) != 0 {
		t.Fatal("unauthorized migration wrote")
	}
	driveDevice(t, e, "8.8.4.4")
	for _, n := range f.nsgs {
		if _, _, _, err := historyTag(n.Tags, "netshift.test.ip-history"); err == nil {
			t.Fatal("old single-IP client would accept migration marker")
		}
	}
}

func TestDeviceInterruptedPGCreateReusesRule(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
	f.failAfter = "pg:create:database:" + own.Rule
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("expected interrupted PG creation")
	}
	driveDevice(t, e, e.State.IP)
	if f.writes["pg:create:database:"+own.Rule] != 1 {
		t.Fatal("retried create after ambiguous success")
	}
	for _, s := range e.State.Action("allow").SharedHistory {
		if s.Pending != nil {
			t.Fatal("pending creation not reconciled")
		}
	}
}
func TestDeviceHistoryDoesNotAdoptOtherUsers(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	other := deviceEngine(t, e.Config, f, "lee@desktop")
	driveDevice(t, other, "1.1.1.1")
	records := []store.HistoryRecord{
		{Status: "verified", Action: "allow", Identity: "sam@laptop", IP: "208.67.222.222", RemovedIPs: []string{"4.2.2.2"}},
		{Status: "verified", Action: "allow", Identity: "lee@desktop", IP: "1.1.1.1", RemovedIPs: []string{"8.8.8.8"}},
	}
	for _, r := range records {
		if err := store.AppendHistory(store.HistoryPath(other.StatePath), r); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := other.loadDevices(context.Background(), other.Config.Actions["allow"])
	if err != nil {
		t.Fatal(err)
	}
	ips, err := other.ownDeviceHistory("allow", other.Config.Actions["allow"], reg)
	if err != nil {
		t.Fatal(err)
	}
	if !sameStrings(ips, []string{"1.1.1.1"}) {
		t.Fatal("cross-owner history leak", ips)
	}
}
func TestDeviceNoExpiryAndSharedNATRetirement(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "8.8.4.4")
	e.Now = func() time.Time { return time.Now().AddDate(2, 0, 0) }
	driveDevice(t, e, "1.1.1.1")
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4", "1.1.1.1")
	driveDevice(t, e, "8.8.4.4")
	if err := e.retireDevice(context.Background(), "allow", e.Config.Actions["allow"], "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
}
func TestRetirementInterruptedLastRuleDeletionRecovers(t *testing.T) {
	e, f := deviceFixture(t)
	for _, n := range f.nsgs {
		n.Rules[0].Sources = []string{"8.8.8.8/32"}
	}
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	f.failAfter = "nsg:delete:one:managed-ip"
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err == nil {
		t.Fatal("expected interrupted retirement")
	}
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	for _, s := range e.State.Action("allow").SharedHistory {
		if s.Pending != nil {
			t.Fatal("retirement left an unreconciled intent")
		}
	}
}

func TestRetiredWriterCleansLatePostgresWrite(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	// A retiring peer can remove active tags while an in-flight owned PG create
	// is finishing. The writer's durable local record still proves ownership.
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
	raw, _ := json.Marshal(fixtureRule(own, "1.1.1.1"))
	var r azureRule
	json.Unmarshal(raw, &r)
	f.pg[own.Server][own.Rule] = r
	if err := e.record(store.HistoryRecord{Status: "verified", Action: "allow", Target: own.ID, IP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	e.State.IP = "1.1.1.1"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); !errors.Is(err, errIdentityRetired) {
		t.Fatal(err)
	}
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("late owned PG write survived retirement")
	}
}

// A tag write that Azure rejected leaves an intent. When the address then
// flips back, the registry already holds the wanted value but not the
// intent's: the intent is superseded instead of failing every retry forever.
func TestRejectedTagWriteThenIPFlipBackReconciles(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	driveDevice(t, e, "1.1.1.1")
	a := e.Config.Actions["allow"]
	key := deviceTag(a, e.Config.Identity, false)
	f.reject = "tag:" + key
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("expected the rejected write to fail")
	}
	slot := config.NSGResourceID(a.Targets[0]) + "#" + key
	rejected := e.pendingWrite("allow", slot)
	if rejected == nil {
		t.Fatal("rejected write left no intent")
	}
	driveDevice(t, e, "1.1.1.1")
	if e.pendingWrite("allow", slot) != nil {
		t.Fatal("stale intent still pending")
	}
	if !slices.ContainsFunc(historyRows(t, e), func(r store.HistoryRecord) bool {
		return r.Status == statusDeviceSuperseded && r.OperationID == rejected.OperationID
	}) {
		t.Fatal("superseded intent missing from history")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "1.1.1.1")
}

// A new tag write never replaces an unresolved intent without a record.
func TestDeviceWriteRecordsTheIntentItSupersedes(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	key := deviceTag(a, e.Config.Identity, false)
	f.reject = "tag:" + key
	e.State.IP = "1.1.1.1"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("expected the rejected write to fail")
	}
	rejected := e.pendingWrite("allow", config.NSGResourceID(a.Targets[0])+"#"+key)
	if rejected == nil {
		t.Fatal("rejected write left no intent")
	}
	driveDevice(t, e, "4.2.2.2")
	if !slices.ContainsFunc(historyRows(t, e), func(r store.HistoryRecord) bool {
		return r.Status == statusDeviceSuperseded && r.OperationID == rejected.OperationID && r.AfterValue == rejected.AfterValue
	}) {
		t.Fatal("overwritten intent missing from history")
	}
}

// Ownership is decided by address. Removing an address that this identity
// did not place, such as one an administrator re-added, is logged.
func TestReconcileLogsRemovalOfAnAddressItDidNotPlace(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	driveDevice(t, e, "1.1.1.1")
	unplaced := func() [][]any {
		var found [][]any
		for _, event := range logEvents(t, &log) {
			if event["event"] == "unplaced_address_removed" {
				found = append(found, []any{event["target"], event["ips"]})
			}
		}
		return found
	}
	if got := unplaced(); len(got) != 0 {
		t.Fatalf("replacing its own address was reported: %v", got)
	}
	one := registryNSG(f, a, 0)
	one.Rules[0].Sources = append(one.Rules[0].Sources, "8.8.4.4/32")
	driveDevice(t, e, "1.1.1.1")
	assertDeviceIPs(t, e, f, "9.9.9.9", "1.1.1.1")
	if got := fmt.Sprint(unplaced()); got != "[[one [8.8.4.4]]]" {
		t.Fatalf("unplaced removals: %s", got)
	}
}

// An unchanged periodic reconcile skips only reads that are provably
// redundant in the same pass; the convergence reloads all remain.
func TestNoOpDeviceReconcileSpawnsOnlyNecessaryCommands(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	var commands []string
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		commands = append(commands, strings.Join(args[:4], " "))
		return f.Run(ctx, program, args, env)
	})
	writes := fmt.Sprint(f.writes)
	driveDevice(t, e, "8.8.4.4")
	// Two registry reads to plan, one PostgreSQL preflight list, then one pass:
	// two registry reloads, one PostgreSQL list, two convergence reads.
	want := []string{
		"network nsg show --subscription", "network nsg show --subscription",
		"postgres flexible-server firewall-rule list",
		"network nsg show --subscription", "network nsg show --subscription",
		"postgres flexible-server firewall-rule list",
		"network nsg show --subscription", "network nsg show --subscription",
	}
	if !slices.Equal(commands, want) {
		t.Fatalf("no-op reconcile ran %d commands:\n%s", len(commands), strings.Join(commands, "\n"))
	}
	if fmt.Sprint(f.writes) != writes {
		t.Fatal("no-op reconcile wrote")
	}
}

// limitHistory sets e's device history limit, which peers made from
// e.Config afterward share.
func limitHistory(t *testing.T, e *Engine, limit int) config.ActionConfig {
	t.Helper()
	a := e.Config.Actions["allow"]
	d := *a.Devices
	d.HistoryLimit = limit
	a.Devices = &d
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	return e.Config.Actions["allow"]
}

// ruleIPs returns the single addresses of every registry rule, per NSG name.
func ruleIPs(t *testing.T, f *deviceCloud) map[string][]string {
	t.Helper()
	got := map[string][]string{}
	for _, n := range f.nsgs {
		for _, source := range n.Rules[0].sourceList() {
			if ip, err := singleIP(source); err == nil {
				got[n.Name] = append(got[n.Name], ip)
			}
		}
	}
	return got
}

// Addresses that other active identities are at (a shared NAT or a VPN
// egress pool) need no pin in this identity's record: their own records keep
// them listed. Pinning them would fill the history limit and leave the
// identity unable to follow its address or retire itself. The active union
// stays.
func TestSharedEgressPoolDoesNotFillTheHistory(t *testing.T) {
	e, f := deviceFixture(t)
	a := limitHistory(t, e, 5)
	pool := []string{"208.67.222.10", "208.67.222.11", "208.67.222.12", "208.67.222.13", "208.67.222.14"}
	for _, ip := range pool {
		driveDevice(t, e, ip)
	}
	for i, ip := range pool {
		driveDevice(t, deviceEngine(t, e.Config, f, fmt.Sprintf("lee@desktop%02d", i)), ip)
	}
	driveDevice(t, e, "1.1.1.1")
	assertDeviceIPs(t, e, f, append([]string{"9.9.9.9", "1.1.1.1"}, pool...)...)
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	assertDeviceIPs(t, e, f, append([]string{"9.9.9.9"}, pool...)...)
	own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("self-retirement left database access")
	}
}

// Pinning keeps an owned address that a registry rule still allows, found
// by case-insensitive rule name like Azure, unless another active identity
// is at it. A retired identity's marker does not count: it may be removed by
// activation, so it cannot be relied on to keep the address listed.
func TestPinningSkipsOnlyOtherActiveIdentitiesAddresses(t *testing.T) {
	e, _ := deviceFixture(t)
	a := limitHistory(t, e, 5)
	reg := newRegistry()
	rule := azureRule{Name: "MANAGED-IP", Sources: []string{"9.9.9.9", "4.4.4.4/32", "1.0.0.1/32", "1.0.0.2"}}
	reg.NSGs[strings.ToLower(config.NSGResourceID(a.Targets[0]))] = azureNSG{Rules: []azureRule{rule}}
	for _, d := range []DeviceRecord{
		{Version: 2, Identity: "lee@desktop", IPs: []string{"1.0.0.1"}, Revision: 1},
		{Version: 2, Identity: "kim@desktop", IPs: []string{"1.0.0.2"}, Revision: 2, Retired: true},
	} {
		if err := reg.merge(d); err != nil {
			t.Fatal(err)
		}
	}
	known := []string{"8.8.4.4", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.4.4.4", "1.0.0.1", "1.0.0.2"}
	d, err := makeDeviceRecord(reg, a, "sam@laptop", "1.1.1.1", known)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.1.1.1", "4.4.4.4", "1.0.0.2", "8.8.4.4", "4.2.2.1"}; !slices.Equal(d.IPs, want) {
		t.Fatalf("record %v, want %v", d.IPs, want)
	}
}

// A record that a late earlier write (or a duplicate installation, or a
// person) put back after this identity's publish is published again, so
// reconciliation never drops the current address.
func TestConvergenceRepublishesARevertedOwnRecord(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	key := deviceTag(a, e.Config.Identity, false)
	old := map[string]string{}
	for id, n := range f.nsgs {
		old[id] = n.Tags[key]
	}
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	tagWrites, reads := 0, 0
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		if args[0] == "tag" {
			tagWrites++
		} else if tagWrites == len(f.nsgs) && args[0] == "network" && args[2] == "show" {
			// After the last read-back, the earlier write lands late.
			if reads++; reads == 2 {
				for id, n := range f.nsgs {
					n.Tags[key] = old[id]
				}
			}
		}
		return f.Run(ctx, program, args, env)
	})
	driveDevice(t, e, "1.1.1.1")
	assertDeviceIPs(t, e, f, "9.9.9.9", "1.1.1.1")
	republished := slices.ContainsFunc(logEvents(t, &log), func(event map[string]any) bool { return event["event"] == "device_record_republished" })
	if !republished {
		t.Fatal("reverted record was not published again")
	}
}

// When this identity's record keeps being replaced, convergence stops with
// an error after its bounded passes, and no rule receipt claims an address
// the rule does not allow.
func TestConvergenceSavesNoReceiptWithoutTheCurrentAddress(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	key := deviceTag(a, e.Config.Identity, false)
	stale := registryNSG(f, a, 0).Tags[key]
	readBack := false
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		out, err := f.Run(ctx, program, args, env)
		if err != nil || args[0] == "tag" {
			readBack = err == nil
			return out, err
		}
		if args[0] != "network" || args[2] != "show" {
			return out, nil
		}
		if readBack {
			readBack = false
			return out, nil
		}
		// Every other registry read shows the stale record again.
		var n azureNSG
		if err = json.Unmarshal(out, &n); err != nil {
			return nil, err
		}
		n.Tags[key] = stale
		return json.Marshal(n)
	})
	e.State.IP = "1.1.1.1"
	err := e.runDevices(context.Background(), "allow", a, "1.1.1.1", false)
	if err == nil || !strings.Contains(err.Error(), "changed during reconciliation") {
		t.Fatalf("convergence with a replaced record: %v", err)
	}
	for _, target := range a.Targets[:2] {
		if got := e.appliedIP("allow", target.ID); got != "8.8.4.4" {
			t.Fatalf("%s receipt %s for an address the rule does not allow", target.ID, got)
		}
	}
	for name, ips := range ruleIPs(t, f) {
		if slices.Contains(ips, "1.1.1.1") {
			t.Fatalf("%s reconciled from a replaced record: %v", name, ips)
		}
	}
}

// Two device actions must not share registry records or PostgreSQL rules.
func TestDeviceActionsCannotShareRegistryOrDatabase(t *testing.T) {
	e, _ := deviceFixture(t)
	base := e.Config.Actions["allow"]
	one, two, db := base.Targets[0], base.Targets[1], base.Targets[2]
	sameNSG := one
	sameNSG.Rule = "other-rule"
	otherDB := db
	otherDB.ID, otherDB.Server = "database2", "database2"
	// The same server under another configured rule name: the per-identity
	// rules on it would still collide.
	sameServer := db
	sameServer.Rule = "other-rule"
	action := func(prefix string, targets ...config.Target) config.ActionConfig {
		a := base
		a.Devices = &config.DevicesConfig{TagPrefix: prefix}
		a.Targets = targets
		return a
	}
	for _, c := range []struct {
		name          string
		first, second config.ActionConfig
		valid         bool
	}{
		{"same NSG and prefix", action("", one, db), action("", sameNSG, otherDB), false},
		{"nested prefixes on one NSG", action("netshift.test.device.", one, db), action("netshift.test.device.extra.", sameNSG, otherDB), false},
		{"shared database", action("", one, db), action("", two, sameServer), false},
		{"separate prefixes on one NSG", action("netshift.test.laptops.", one, db), action("netshift.test.servers.", sameNSG, otherDB), true},
		{"separate NSGs and databases", action("", one, db), action("", two, otherDB), true},
	} {
		// validate reports the conflict; BindIdentity enforces it again at
		// run time for profiles loaded some other way.
		cfg := e.Config
		cfg.Actions = map[string]config.ActionConfig{"first": c.first, "second": c.second}
		if err := cfg.Validate(); (err == nil) != c.valid {
			t.Errorf("%s: validate: valid=%v, got %v", c.name, c.valid, err)
		}
		if err := BindIdentity(cfg, store.New()); (err == nil) != c.valid {
			t.Errorf("%s: bindIdentity: valid=%v, got %v", c.name, c.valid, err)
		}
	}
}

// Tag keys ignore case in Azure: a verified write recorded under the stored
// spelling of this identity's key is still its ownership evidence.
func TestOwnHistoryMatchesTagKeysIgnoringCase(t *testing.T) {
	e, _ := deviceFixture(t)
	a := e.Config.Actions["allow"]
	raw, err := encodeDevice(DeviceRecord{Version: 2, Identity: e.Config.Identity, IPs: []string{"4.2.2.2", "4.2.2.1"}, Revision: 3}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.record(store.HistoryRecord{Status: statusDeviceVerified, Action: "allow", Target: "registry", Tag: strings.ToUpper(deviceTag(a, e.Config.Identity, false)), AfterValue: raw}); err != nil {
		t.Fatal(err)
	}
	ips, err := e.ownDeviceHistory("allow", a, newRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(ips, []string{"4.2.2.2", "4.2.2.1"}) {
		t.Fatalf("own history %v lacks the recorded record's addresses", ips)
	}
}

// A single-IP or mapped plan left pending from before devices mode is
// recorded superseded when a device receipt replaces it, not dropped.
func TestDeviceReceiptRecordsTheTargetPlanItReplaces(t *testing.T) {
	e, _ := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	s := e.State.Action("allow").Target(a.Targets[0].ID)
	s.PendingIP = "1.1.1.1"
	s.PendingChange = &store.HistoryRecord{Status: statusIntent, Action: "allow", Target: a.Targets[0].ID, IP: "1.1.1.1", OperationID: "plan-before-devices"}
	driveDevice(t, e, "8.8.4.4")
	if s := e.State.Action("allow").Target(a.Targets[0].ID); s.PendingChange != nil || s.PendingIP != "" {
		t.Fatal("pending plan kept")
	}
	if !slices.ContainsFunc(historyRows(t, e), func(r store.HistoryRecord) bool {
		return r.Status == statusSuperseded && r.OperationID == "plan-before-devices"
	}) {
		t.Fatal("replaced plan missing from history")
	}
}

// The tag prefix is stored lowercase, as Azure compares tag keys ignoring
// case; a migration marker written under a mixed-case prefix still counts.
func TestDeviceTagPrefixIsLowercased(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	d := *a.Devices
	d.TagPrefix = "netshift.Test.Device."
	a.Devices = &d
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	a = e.Config.Actions["allow"]
	if a.Devices.TagPrefix != "netshift.test.device." {
		t.Fatalf("prefix %q", a.Devices.TagPrefix)
	}
	marker := legacyMarker{Mode: "devices", Owner: a.Devices.LegacyIdentity, Prefix: "netshift.Test.Device.", Version: 2}
	raw, _ := json.Marshal(marker)
	for _, n := range f.nsgs {
		n.Tags["netshift.test.ip-history"] = string(raw)
	}
	reg, err := e.loadDevices(context.Background(), a)
	if err != nil || len(reg.LegacyIPs) != 0 {
		t.Fatalf("mixed-case migration marker: %v %v", reg.LegacyIPs, err)
	}
}

// A template description is restored as one argument, so one that starts
// with "-" is not read as an option; one that starts with "@" would be read
// as a file name, so the profile is refused.
func TestTemplateDescriptionIsRestoredAsOneArgument(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	bad := a
	bad.Targets = slices.Clone(a.Targets)
	tpl := *bad.Targets[0].Template
	tpl.Description = "@notes.txt"
	bad.Targets[0].Template = &tpl
	cfg := e.Config
	cfg.Actions = map[string]config.ActionConfig{"allow": bad}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cannot start with @") {
		t.Fatalf("description starting with @: %v", err)
	}
	for _, n := range f.nsgs {
		n.Rules[0].Sources = []string{"8.8.8.8/32"}
		n.Rules[0].Description = "-managed by ops"
	}
	for i := range a.Targets[:2] {
		tpl := *a.Targets[i].Template
		tpl.Description = "-managed by ops"
		a.Targets[i].Template = &tpl
	}
	e.Config.Actions["allow"] = a
	driveDevice(t, e, "8.8.4.4")
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	if err := e.activateDevice(context.Background(), "allow", a); err != nil {
		t.Fatal(err)
	}
	var creates [][]string
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		if args[0] == "network" && args[3] == "create" {
			creates = append(creates, args)
		}
		return f.Run(ctx, program, args, env)
	})
	e.State.IP = "1.1.1.1"
	if err := e.runDevices(context.Background(), "allow", a, "1.1.1.1", true); err != nil {
		t.Fatal(err)
	}
	if len(creates) != 2 {
		t.Fatalf("restored %d rules", len(creates))
	}
	for _, args := range creates {
		if !slices.Contains(args, "--description=-managed by ops") || slices.Contains(args, "--description") {
			t.Fatalf("description not passed as one argument: %q", args)
		}
	}
	for _, n := range f.nsgs {
		if n.Rules[0].Description != "-managed by ops" {
			t.Fatalf("%s description %q", n.Name, n.Rules[0].Description)
		}
	}
}

// Malformed Azure JSON is reported with the resource it came from.
func TestMalformedAzureJSONNamesTheResource(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		if args[0] == "network" && args[2] == "show" && argValue(args, "--name") == "two" {
			return []byte("not json"), nil
		}
		if args[0] == "postgres" && args[3] == "list" {
			return []byte("{"), nil
		}
		return f.Run(ctx, program, args, env)
	})
	if _, err := e.readSharedNSG(context.Background(), a, a.Targets[1]); err == nil || !strings.Contains(err.Error(), "NSG two") {
		t.Fatalf("NSG read: %v", err)
	}
	if _, err := e.listDevicePG(context.Background(), a, a.Targets[2]); err == nil || !strings.Contains(err.Error(), "server database") {
		t.Fatalf("PostgreSQL list: %v", err)
	}
}
