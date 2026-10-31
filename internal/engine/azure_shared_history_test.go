package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

type historyRunner struct {
	base         *fakeRunner
	tags         map[string]map[string]string
	tagWrites    int
	nsgReads     int
	beforeTag    func()
	afterTag     func(map[string]string)
	failTag      bool
	ambiguousTag bool
}

// argValue returns the value of option key in args, given either as two
// arguments or as one "key=value" argument, like the Azure CLI accepts.
func argValue(args []string, key string) string {
	for i, value := range args {
		if value == key && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(value, key+"="); ok {
			return v
		}
	}
	return ""
}
func (r *historyRunner) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	if len(args) > 2 && args[0] == "network" && args[1] == "nsg" && args[2] == "show" {
		r.nsgReads++
		name := argValue(args, "--name")
		rule, ok := r.base.rules[name]
		if !ok {
			return nil, errors.New("NSG not found")
		}
		return json.Marshal(map[string]any{"id": strings.Split(rule["id"].(string), "/securityRules/")[0], "name": name, "tags": r.tags[name], "securityRules": []any{rule}})
	}
	if len(args) > 1 && args[0] == "tag" && args[1] == "update" {
		if argValue(args, "--operation") != "Merge" {
			return nil, errors.New("tag replacement forbidden")
		}
		if r.beforeTag != nil {
			r.beforeTag()
		}
		if r.failTag && !r.ambiguousTag {
			return nil, errors.New("tag update denied")
		}
		id := argValue(args, "--resource-id")
		name := id[strings.LastIndex(id, "/")+1:]
		entry := strings.SplitN(argValue(args, "--tags"), "=", 2)
		if len(entry) != 2 {
			return nil, errors.New("bad tag argv")
		}
		if r.tags[name] == nil {
			r.tags[name] = map[string]string{}
		}
		r.tags[name][entry[0]] = entry[1]
		r.tagWrites++
		if r.afterTag != nil {
			r.afterTag(r.tags[name])
		}
		if r.failTag {
			r.failTag = false
			return nil, context.DeadlineExceeded
		}
		return []byte(`{}`), nil
	}
	return r.base.Run(ctx, program, args, env)
}
func cachedJSON(ips ...string) string {
	data, _ := json.Marshal(IPHistory{Version: 1, IPs: ips})
	return string(data)
}
func enableShared(t *testing.T, e *Engine, r *fakeRunner) *historyRunner {
	t.Helper()
	a := e.Config.Actions["allow"]
	a.SharedIPHistory = &config.SharedIPHistoryConfig{Tag: "netshift.test.ip-history", Limit: 10}
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	runner := &historyRunner{base: r, tags: map[string]map[string]string{}}
	e.Runner = runner
	return runner
}
func TestSharedHistoryFreshMachinesTakeOverWithoutSyncedState(t *testing.T) {
	nsg, pg := fixtureTarget("one", "nsg"), fixtureTarget("db", "postgres")
	first, base, _ := fixtureEngine(t, nsg, pg)
	r := enableShared(t, first, base)
	r.tags["one"] = map[string]string{"env": "production", "comment": "human = text, preserved", "netshift.test.ip-history": cachedJSON("9.9.9.9")}
	base.rules["one"] = fixtureRule(nsg, "9.9.9.9")
	base.rules["db"] = fixtureRule(pg, "9.9.9.9")
	if err := first.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	second := &Engine{Config: first.Config, State: store.New(), Apply: true, Runner: r, Save: func(*store.State) error { return nil }, History: func(store.HistoryRecord) error { return nil }}
	if err := second.step(context.Background(), confirmed("4.4.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	if base.rules["one"]["sourceAddressPrefix"] != "4.4.4.4/32" || base.rules["db"]["startIpAddress"] != "4.4.4.4" {
		t.Fatal("fresh machine did not replace cloud-known IP")
	}
	if r.tags["one"]["env"] != "production" || r.tags["one"]["comment"] != "human = text, preserved" || base.rules["one"]["description"] != "keep this exactly" {
		t.Fatal("comments or other tags changed")
	}
	_, _, record, err := historyTag(r.tags["one"], "netshift.test.ip-history")
	if err != nil || !reflect.DeepEqual(record.IPs, []string{"4.4.4.4", "8.8.4.4", "9.9.9.9", "8.8.8.8"}) {
		t.Fatalf("history=%+v %v", record, err)
	}
	// The first machine retains its own old local state, yet can take over later.
	if err := first.step(context.Background(), confirmed("208.67.222.222"), true, true); err != nil {
		t.Fatal(err)
	}
	if base.rules["one"]["sourceAddressPrefix"] != "208.67.222.222/32" {
		t.Fatal("old local state blocked takeover")
	}
	reads, writes := r.nsgReads, r.tagWrites
	if err := first.step(context.Background(), confirmed("208.67.222.222"), false, false); err != nil {
		t.Fatal(err)
	}
	if r.nsgReads != reads || r.tagWrites != writes {
		t.Fatal("stable poll accessed Azure metadata")
	}
}
func TestSharedHistoryUsesLocalJournalWithoutLearningOtherSources(t *testing.T) {
	e, base, target := mappedFixture(t, []string{"4.4.4.4/32", "1.1.1.1"})
	r := enableShared(t, e, base)
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	if err := store.AppendHistory(store.HistoryPath(e.StatePath), store.HistoryRecord{Action: "allow", Target: target.ID, Status: "verified", IP: "4.4.4.4", BeforeSources: []string{"1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base.rules["shared"]["sourceAddressPrefixes"], []string{"8.8.4.4/32", "1.1.1.1"}) {
		t.Fatal("unrelated source removed")
	}
	_, _, record, err := historyTag(r.tags["shared"], "netshift.test.ip-history")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range record.IPs {
		if ip == "1.1.1.1" {
			t.Fatal("learned another user's IP")
		}
	}
}
func TestSharedHistoryStrictVersionedJSON(t *testing.T) {
	for _, bad := range []string{"human comments", `{"ips":["8.8.8.8"]}`, `{"v":2,"ips":["8.8.8.8"]}`, `{"v":1,"ips":[]}`, `{"v":1,"ips":["8.8.8.0/24"]}`, `{"v":1,"ips":["10.0.0.1"]}`, `{"v":1,"ips":["8.8.8.8","8.8.8.8"]}`, `{"v":1,"ips":["8.8.8.8"],"unknown":true}`, `{"v":1,"ips":["8.8.8.8"]} {}`} {
		if _, _, _, err := historyTag(map[string]string{"netshift.test.ip-history": bad}, "netshift.test.ip-history"); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	key, _, _, err := historyTag(map[string]string{"NetShift.Test.IP-History": cachedJSON("8.8.8.8")}, "netshift.test.ip-history")
	if err != nil || key != "NetShift.Test.IP-History" {
		t.Fatal("lost case-insensitive key identity")
	}
}
func TestSharedHistoryRetentionKeepsTenAndCurrentReferences(t *testing.T) {
	target := fixtureTarget("one", "nsg")
	ips := []string{}
	for i := 100; i < 110; i++ {
		ips = append(ips, fmt.Sprintf("201.201.201.%d", i))
	}
	nsg := azureNSG{Tags: map[string]string{"netshift.test.ip-history": cachedJSON(ips...)}, Rules: []azureRule{{ID: expectedResourceID(target), Source: ips[9] + "/32"}}}
	action := config.ActionConfig{Targets: []config.Target{target}, SharedIPHistory: &config.SharedIPHistoryConfig{Tag: "netshift.test.ip-history", Limit: 10}}
	_, _, after, _, err := historyPlan(nsg, action, "8.8.4.4", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, record, err := historyTag(map[string]string{"netshift.test.ip-history": after}, "netshift.test.ip-history")
	if err != nil || len(record.IPs) != 10 || record.IPs[0] != "8.8.4.4" || record.IPs[1] != ips[9] || len(after) > 256 {
		t.Fatalf("retention: %s (%v)", after, err)
	}
	nsg.Rules[0].Source = ""
	nsg.Rules[0].Sources = ips
	if _, _, _, _, err := historyPlan(nsg, action, "8.8.4.4", nil); err == nil {
		t.Fatal("evicted an IP still referenced during partial updates")
	}
}
func TestMalformedRegistryAndTagLimitBlockEveryWrite(t *testing.T) {
	for _, limit := range []bool{false, true} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"), fixtureTarget("two", "nsg"))
			r := enableShared(t, e, base)
			r.tags["two"] = map[string]string{}
			if limit {
				for i := range 50 {
					r.tags["two"][fmt.Sprint(i)] = "preserve"
				}
			} else {
				r.tags["two"]["netshift.test.ip-history"] = "human comment"
			}
			if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil {
				t.Fatal("invalid cache accepted")
			}
			if r.tagWrites != 0 || updates(base) != 0 {
				t.Fatal("mutated before validating all registries")
			}
		})
	}
}
func TestSharedHistoryIntentAndAmbiguousRecovery(t *testing.T) {
	e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	r := enableShared(t, e, base)
	var records []store.HistoryRecord
	e.History = func(rec store.HistoryRecord) error { records = append(records, rec); return nil }
	var saved store.State
	e.Save = func(state *store.State) error { data, _ := json.Marshal(state); return json.Unmarshal(data, &saved) }
	r.beforeTag = func() {
		if len(records) == 0 || records[len(records)-1].Status != "metadata_intent" {
			t.Fatal("metadata mutation without journal intent")
		}
		if len(saved.Action("allow").SharedHistory) != 1 {
			t.Fatal("metadata mutation without persisted state")
		}
	}
	r.failTag, r.ambiguousTag = true, true
	action := e.Config.Actions["allow"]
	event := store.Event{IP: "8.8.4.4"}
	if err := e.runAzure(context.Background(), "allow", action, event, true); err == nil {
		t.Fatal("expected timeout")
	}
	if updates(base) != 0 {
		t.Fatal("rule changed before tag could be verified")
	}
	e.State = &saved
	if err := e.runAzure(context.Background(), "allow", action, event, true); err != nil {
		t.Fatal(err)
	}
	if r.tagWrites != 1 || updates(base) != 1 {
		t.Fatal("replayed ambiguous metadata mutation")
	}
	found := false
	for _, rec := range records {
		if rec.Status == "metadata_reconciled" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing recovered metadata receipt")
	}
}
func TestSharedHistoryDryRunAndJournalFailureNeverWrite(t *testing.T) {
	for _, dry := range []bool{true, false} {
		t.Run(fmt.Sprint(dry), func(t *testing.T) {
			e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
			r := enableShared(t, e, base)
			e.Apply = !dry
			e.History = func(store.HistoryRecord) error {
				if dry {
					t.Fatal("dry run journal write")
				}
				return errors.New("disk full")
			}
			err := e.step(context.Background(), confirmed("8.8.4.4"), true, true)
			if !dry && err == nil {
				t.Fatal("missing journal failure")
			}
			if dry && err != nil {
				t.Fatal(err)
			}
			if r.tagWrites != 0 || updates(base) != 0 {
				t.Fatal("unsafe write")
			}
		})
	}
}
func TestSharedHistoryMergeConflictStopsSourceWrite(t *testing.T) {
	e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	r := enableShared(t, e, base)
	r.afterTag = func(tags map[string]string) { tags["netshift.test.ip-history"] = cachedJSON("9.9.9.9") }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil {
		t.Fatal("cache conflict not detected")
	}
	if updates(base) != 0 {
		t.Fatal("updated source after cache conflict")
	}
}
func TestSharedHistoryEnablementInvalidatesPriorReceipts(t *testing.T) {
	e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	if err := e.step(context.Background(), confirmed("8.8.8.8"), true, true); err != nil {
		t.Fatal(err)
	}
	r := enableShared(t, e, base)
	base.rules["one"]["sourceAddressPrefix"] = "9.9.9.9/32"
	r.tags["one"] = map[string]string{"netshift.test.ip-history": cachedJSON("9.9.9.9")}
	if err := e.step(context.Background(), confirmed("8.8.8.8"), false, false); err != nil {
		t.Fatal(err)
	}
	if updates(base) != 1 {
		t.Fatal("old local receipt skipped the shared-ownership reconciliation")
	}
}
func TestHistoryTailRingPreservesOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	for i := range 7 {
		if err := store.AppendHistory(path, store.HistoryRecord{Target: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ReadHistory(path, 3, "")
	if err != nil || len(records) != 3 || records[0].Target != "4" || records[1].Target != "5" || records[2].Target != "6" {
		t.Fatalf("tail: %+v %v", records, err)
	}
}

func TestSharedHistoryRecheckedAfterRuleUpdate(t *testing.T) {
	e, base, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	r := enableShared(t, e, base)
	base.afterUpdate = func() { r.tags["one"]["netshift.test.ip-history"] = cachedJSON("9.9.9.9") }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	_, _, record, err := historyTag(r.tags["one"], "netshift.test.ip-history")
	if err != nil || record.IPs[0] != "8.8.4.4" || !strings.Contains(r.tags["one"]["netshift.test.ip-history"], "9.9.9.9") {
		t.Fatalf("post-update merge: %+v %v", record, err)
	}
}

// recentHistoryIPs streams the journal but must return exactly what walking
// the newest window records backward returns, keeping each address's first
// occurrence: order decides which addresses a bounded history retains.
func TestRecentHistoryIPsMatchesABackwardWalk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.history.jsonl")
	pool := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "4.2.2.2", "208.67.222.222", " 4.2.2.2", "10.0.0.1", ""}
	random := rand.New(rand.NewPCG(1, 2))
	statuses := []string{statusVerified, statusIntent, statusDeviceVerified, statusFailed, statusBaseline}
	var journal []byte
	for range 300 {
		r := store.HistoryRecord{Action: "allow", Status: statuses[random.IntN(len(statuses))], IP: pool[random.IntN(len(pool))]}
		for range random.IntN(3) {
			r.RemovedIPs = append(r.RemovedIPs, pool[random.IntN(len(pool))])
		}
		line, _ := json.Marshal(r)
		journal = append(append(journal, line...), '\n')
	}
	if err := os.WriteFile(path, journal, 0600); err != nil {
		t.Fatal(err)
	}
	pick := func(r store.HistoryRecord, add func(string)) {
		if r.Status != statusFailed {
			add(r.IP)
			for _, ip := range r.RemovedIPs {
				add(ip)
			}
		}
	}
	for _, window := range []int{1, 2, 7, 50, 299, 300, 100000} {
		rows, err := store.ReadHistory(path, window, "")
		if err != nil {
			t.Fatal(err)
		}
		var walked []string
		for _, r := range slices.Backward(rows) {
			pick(r, func(ip string) { walked = append(walked, ip) })
		}
		got, err := recentHistoryIPs(path, window, pick)
		if err != nil {
			t.Fatal(err)
		}
		if want := uniqueIPs(walked); !slices.Equal(got, want) {
			t.Fatalf("window %d: got %v want %v", window, got, want)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"partial\":\n")
	_ = f.Close()
	if _, err := recentHistoryIPs(path, ownershipWindow, pick); err == nil {
		t.Fatal("corrupt journal accepted")
	}
	if ips, err := recentHistoryIPs(filepath.Join(t.TempDir(), "missing.jsonl"), 10, pick); err != nil || len(ips) != 0 {
		t.Fatal("missing journal is not empty", ips, err)
	}
}

// Every ownership reader accepts exactly the verified receipts.
func TestOwnershipEvidenceIsOneSet(t *testing.T) {
	all := []string{statusIntent, statusVerified, statusReconciled, statusSuperseded, statusBaseline, statusFailed,
		statusMetadataIntent, statusMetadataVerified, statusMetadataReconciled, statusMetadataSuperseded, statusMetadataFailed,
		statusDeviceIntent, statusDeviceCreateIntent, statusDeviceDeleteIntent, statusDeviceVerified, statusDeviceReconciled, statusDeviceSuperseded}
	receipts := []string{statusVerified, statusReconciled, statusBaseline, statusMetadataVerified, statusMetadataReconciled, statusDeviceVerified, statusDeviceReconciled}
	if got := slices.DeleteFunc(slices.Clone(all), func(s string) bool { return !provesOwnership(s) }); !sameStrings(got, receipts) {
		t.Fatalf("ownership evidence = %v, want every verified receipt %v", got, receipts)
	}
	for _, status := range all {
		e, _ := deviceFixture(t)
		r := store.HistoryRecord{Action: "allow", Identity: e.Config.Identity, Status: status, IP: "4.2.2.2"}
		if err := store.AppendHistory(store.HistoryPath(e.StatePath), r); err != nil {
			t.Fatal(err)
		}
		device, err := e.ownDeviceHistory("allow", e.Config.Actions["allow"], newRegistry())
		if err != nil {
			t.Fatal(err)
		}
		shared, err := e.actionKnownIPs("allow", e.Config.Actions["allow"])
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := recentHistoryIPs(store.HistoryPath(e.StatePath), ownershipWindow, ownershipIPs)
		if err != nil {
			t.Fatal(err)
		}
		want := provesOwnership(status)
		if containsIP(device, "4.2.2.2") != want || containsIP(shared, "4.2.2.2") != want || containsIP(knownIPs(e.Config, e.State, mapped), "4.2.2.2") != want {
			t.Errorf("%s: readers disagree with provesOwnership=%v", status, want)
		}
	}
}
