package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
	"runtime"
)

func mappedFixture(t *testing.T, sources []string) (*Engine, *fakeRunner, config.Target) {
	t.Helper()
	target := fixtureTarget("shared", "nsg")
	e, r, _ := fixtureEngine(t, target)
	rule := r.rules["shared"]
	rule["sourceAddressPrefix"] = ""
	rule["sourceAddressPrefixes"] = sources
	var snapshot azureRule
	b, _ := json.Marshal(rule)
	if err := json.Unmarshal(b, &snapshot); err != nil {
		t.Fatal(err)
	}
	target.SourceMode = "replace_known"
	target.KnownIPs = []string{"8.8.8.8", "9.9.9.9"}
	target.RuleShape = ruleShape(snapshot)
	target.BootstrapIP, target.Destination = "", ""
	target.Ports = nil
	target.Priority = 0
	a := e.Config.Actions["allow"]
	a.Targets = []config.Target{target}
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	return e, r, target
}

func TestMappedReplacementPreservesOtherSources(t *testing.T) {
	tests := []struct {
		name          string
		before, after []string
		changes       int
	}{
		{"replace-two", []string{"1.1.1.1/32", "8.8.8.8/32", "203.0.113.7/32", "9.9.9.9", "8.8.8.0/24", "VirtualNetwork"}, []string{"1.1.1.1/32", "8.8.4.4/32", "203.0.113.7/32", "8.8.8.0/24", "VirtualNetwork"}, 1},
		{"already-present", []string{"8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9/32", "1.1.1.1"}, []string{"1.1.1.1", "8.8.4.4", "1.1.1.1"}, 1},
		{"no-op", []string{"1.1.1.1", "8.8.4.4"}, []string{"1.1.1.1", "8.8.4.4"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, r, target := mappedFixture(t, tt.before)
			before, _ := json.Marshal(r.rules["shared"])
			if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(r.rules["shared"])
			var result azureRule
			_ = json.Unmarshal(after, &result)
			if !reflect.DeepEqual(result.sourceList(), tt.after) {
				t.Fatalf("sources: %v", result.sourceList())
			}
			if !reflect.DeepEqual(immutableRule(before), immutableRule(after)) {
				t.Fatal("changed non-source fields")
			}
			if updates(r) != tt.changes {
				t.Fatalf("updates: %d", updates(r))
			}
			for _, call := range r.calls {
				for _, arg := range call {
					if arg == "create" || arg == "delete" {
						t.Fatal("created/deleted a rule")
					}
				}
			}
			if !e.State.Action("allow").Target(target.ID).HistoryInitialized {
				t.Fatal("history not initialized")
			}
		})
	}
}

func TestMappedSourceGuards(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unowned", func(r map[string]any) { r["sourceAddressPrefixes"] = []string{"1.1.1.1", "8.8.8.0/24"} }},
		{"permissions", func(r map[string]any) { r["access"] = "Deny" }},
		{"outbound", func(r map[string]any) { r["direction"] = "Outbound" }},
		{"ports", func(r map[string]any) { r["destinationPortRanges"] = []string{"3389"} }},
		{"destination", func(r map[string]any) { r["destinationAddressPrefix"] = "*" }},
		{"source-port", func(r map[string]any) { r["sourcePortRange"] = "22" }},
		{"asg", func(r map[string]any) { r["sourceApplicationSecurityGroups"] = []any{map[string]any{"id": "group"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, r, _ := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
			test.change(r.rules["shared"])
			if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil || updates(r) != 0 {
				t.Fatal("unsafe mapped update accepted")
			}
		})
	}
}

func TestMappedFreshReadRejectsConcurrentChanges(t *testing.T) {
	e, r, _ := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	shows := 0
	r.beforeShow = func() {
		shows++
		if shows == 2 {
			r.rules["shared"]["sourceAddressPrefixes"] = []string{"8.8.8.8", "1.1.1.1", "4.4.4.4"}
		}
	}
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil || updates(r) != 0 {
		t.Fatal("stale list overwritten")
	}
}

func TestMappedMissingSourceCannotBecomeSuccessOnRetry(t *testing.T) {
	e, r, target := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	r.afterUpdate = func() { r.rules["shared"]["sourceAddressPrefixes"] = []string{"8.8.4.4/32"} }
	a := e.Config.Actions["allow"]
	state := e.State.Action("allow").Target(target.ID)
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "8.8.4.4"); err == nil {
		t.Fatal("lost source accepted")
	}
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "8.8.4.4"); err == nil {
		t.Fatal("retry silently accepted lost source")
	}
	if state.AppliedIP != "" {
		t.Fatal("failure recorded as success")
	}
}

func TestMappedHistoryAndInterruptedWrite(t *testing.T) {
	e, r, target := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	var rows []store.HistoryRecord
	e.History = func(rec store.HistoryRecord) error { rows = append(rows, rec); return nil }
	r.beforeUpdate = func() {
		if len(rows) != 1 || rows[0].Status != "intent" || rows[0].OperationID == "" {
			t.Fatal("missing durable history intent")
		}
	}
	r.failUpdate["shared"], r.ambiguous = 1, true
	a := e.Config.Actions["allow"]
	state := e.State.Action("allow").Target(target.ID)
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "8.8.4.4"); err == nil {
		t.Fatal("expected ambiguous timeout")
	}
	encoded, _ := json.Marshal(e.State)
	var restarted store.State
	if err := json.Unmarshal(encoded, &restarted); err != nil {
		t.Fatal(err)
	}
	e.State = &restarted
	state = e.State.Action("allow").Target(target.ID)
	r.rules["shared"]["sourceAddressPrefixes"] = []string{"8.8.4.4/32", "1.1.1.1", "4.4.4.4"}
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "8.8.4.4"); err != nil {
		t.Fatal(err)
	}
	if updates(r) != 1 || rows[1].Status != "reconciled" || rows[1].OperationID != rows[0].OperationID {
		t.Fatalf("bad reconciliation: %+v", rows)
	}
	if state.PendingChange != nil || state.AppliedIP != "8.8.4.4" {
		t.Fatal("pending operation not finalized")
	}
}

func TestHistoryFailureBlocksCloudWrite(t *testing.T) {
	e, r, _ := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	e.History = func(store.HistoryRecord) error { return errors.New("disk full") }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err == nil || updates(r) != 0 {
		t.Fatal("updated without durable history")
	}
}

func TestMappedDryRunDoesNotWriteHistory(t *testing.T) {
	e, r, _ := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	e.Apply = false
	e.History = func(store.HistoryRecord) error { t.Fatal("dry run wrote history"); return nil }
	e.Save = func(*store.State) error { t.Fatal("dry run wrote state"); return nil }
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil || updates(r) != 0 {
		t.Fatalf("dry run: %v", err)
	}
}

func TestRuleShapeNormalizesAzureEmptyRepresentations(t *testing.T) {
	r := azureRule{Access: "Allow", Direction: "Inbound", Protocol: "TCP", Priority: 1040, Destination: "*", Port: "22", SourcePort: "*"}
	changed := r
	changed.SourceASGs, changed.DestinationASGs = []json.RawMessage{}, []json.RawMessage{}
	changed.Protocol = "Tcp"
	changed.Port, changed.Ports = "", []string{"22"}
	if ruleShape(r) != ruleShape(changed) {
		t.Fatal("equivalent Azure forms differ")
	}
}

func TestHistoryBaselineUpgradeIsQuietAfterInitialization(t *testing.T) {
	target := fixtureTarget("one", "nsg")
	e, r, _ := fixtureEngine(t, target)
	if err := e.step(context.Background(), confirmed("8.8.8.8"), true, true); err != nil {
		t.Fatal(err)
	}
	state := e.State.Action("allow").Target(target.ID)
	state.HistoryInitialized = false // v0.1 state has no history field.
	var rows []store.HistoryRecord
	e.History = func(rec store.HistoryRecord) error { rows = append(rows, rec); return nil }
	if err := e.step(context.Background(), confirmed("8.8.8.8"), false, false); err != nil {
		t.Fatal(err)
	}
	calls := len(r.calls)
	if len(rows) != 1 || rows[0].Status != "baseline" {
		t.Fatalf("baseline: %+v", rows)
	}
	if err := e.step(context.Background(), confirmed("8.8.8.8"), false, false); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(r.calls) != calls || updates(r) != 0 {
		t.Fatal("unchanged poll did extra work")
	}
}

func TestHistoryJournalPreservesAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.history.jsonl")
	for _, id := range []string{"one", "two", "one"} {
		if err := store.AppendHistory(path, store.HistoryRecord{At: time.Now().UTC(), Status: "verified", Target: id, IP: "8.8.8.8"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ReadHistory(path, 1, "one")
	if err != nil || len(rows) != 1 || rows[0].Target != "one" {
		t.Fatalf("read: %v %v", rows, err)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("journal permissions")
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString("{\"partial\":")
	_ = f.Close()
	before, _ := os.ReadFile(path)
	if err := store.AppendHistory(path, store.HistoryRecord{}); err == nil {
		t.Fatal("accepted truncated history")
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("overwrote history")
	}
	if _, err := store.ReadHistory(path, 50, ""); err == nil {
		t.Fatal("silently read corrupt history")
	}
}

func TestMappingUsesExactOwnershipAndPreservesExistingTargets(t *testing.T) {
	original := fixtureTarget("owned", "nsg")
	pg := fixtureTarget("db", "postgres")
	e, _, _ := fixtureEngine(t, original, pg)
	baseID, _, _ := strings.Cut(expectedResourceID(original), "/securityRules/")
	var rule azureRule
	data, _ := json.Marshal(fixtureRule(original, "8.8.8.8"))
	_ = json.Unmarshal(data, &rule)
	shared := rule
	shared.Name, shared.ID = "existing-shared", baseID+"/securityRules/existing-shared"
	shared.Source, shared.Sources = "", []string{"9.9.9.9/32", "1.1.1.1", "9.9.9.0/24"}
	unowned := rule
	unowned.Name, unowned.ID, unowned.Source = "named-workstation", baseID+"/securityRules/named-workstation", "8.8.8.9/32"
	denied := shared
	denied.Name, denied.ID, denied.Access = "denied", baseID+"/securityRules/denied", "Deny"
	nsgs := []azureNSG{{Name: original.NSG, ID: baseID, ResourceGroup: original.ResourceGroup, Rules: []azureRule{rule, shared, unowned, denied}, Defaults: []azureRule{shared}}, {Name: "inventory-only", ID: baseID + "-empty"}}
	m := buildMapping(subscriptionInfo{ID: original.Subscription, Name: "test"}, nsgs, e.Config, []string{"8.8.8.8", "9.9.9.9"})
	if len(m.NSGs) != 2 || m.CustomRules != 4 || m.DefaultRules != 1 || m.MatchedRules != 2 || m.MatchedNSGs != 1 {
		t.Fatalf("bad counts: %+v", m)
	}
	next, err := mergeMapping(e.Config, m, "allow")
	if err != nil {
		t.Fatal(err)
	}
	targets := next.Actions["allow"].Targets
	if len(targets) != 3 || !reflect.DeepEqual(targets[:2], e.Config.Actions["allow"].Targets) {
		t.Fatal("existing targets changed")
	}
	if targets[2].Rule != shared.Name || targets[2].SourceMode != "replace_known" || !reflect.DeepEqual(targets[2].KnownIPs, []string{"9.9.9.9"}) {
		t.Fatalf("bad adoption: %+v", targets[2])
	}
	if len(e.Config.Actions["allow"].Targets) != 2 {
		t.Fatal("merge mutated original config")
	}
	missing := buildMapping(m.Subscription, nil, e.Config, m.KnownIPs)
	if _, err := mergeMapping(e.Config, missing, "allow"); err == nil {
		t.Fatal("missing configured rule ignored")
	}
}

func TestKnownIPRegistryNeverLearnsOtherSharedSources(t *testing.T) {
	e, _, _ := fixtureEngine(t, fixtureTarget("one", "nsg"))
	e.Config.KnownIPs = []string{"9.9.9.9"}
	path := filepath.Join(t.TempDir(), "state.history.jsonl")
	for _, r := range []store.HistoryRecord{
		{Status: statusVerified, IP: "8.8.4.4", RemovedIPs: []string{"4.4.4.4"}, BeforeSources: []string{"1.1.1.1"}, AfterSources: []string{"1.0.0.1"}},
		{Status: statusFailed, IP: "208.67.222.222"},
	} {
		if err := store.AppendHistory(path, r); err != nil {
			t.Fatal(err)
		}
	}
	history, err := recentHistoryIPs(path, ownershipWindow, ownershipIPs)
	if err != nil {
		t.Fatal(err)
	}
	got := knownIPs(e.Config, e.State, history)
	want := []string{"4.4.4.4", "8.8.4.4", "8.8.8.8", "9.9.9.9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("registry: %v", got)
	}
}

func TestMappedNewIPAfterInterruptedWriteUsesRecordedOwnership(t *testing.T) {
	e, r, target := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	var rows []store.HistoryRecord
	e.History = func(rec store.HistoryRecord) error { rows = append(rows, rec); return nil }
	a := e.Config.Actions["allow"]
	state := e.State.Action("allow").Target(target.ID)
	r.failUpdate["shared"], r.ambiguous = 1, true
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "8.8.4.4"); err == nil {
		t.Fatal("expected interrupted update")
	}
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "4.4.4.4"); err != nil {
		t.Fatal(err)
	}
	if state.AppliedIP != "4.4.4.4" || state.PendingChange != nil {
		t.Fatal("latest IP not adopted")
	}
	if len(rows) != 4 || rows[1].Status != "superseded" || rows[3].Status != "verified" {
		t.Fatalf("history: %+v", rows)
	}
	if !reflect.DeepEqual(r.rules["shared"]["sourceAddressPrefixes"], []string{"4.4.4.4/32", "1.1.1.1"}) {
		t.Fatal("unrelated source changed")
	}
	if err := e.azureTarget(context.Background(), "allow", a, target, state, "208.67.222.222"); err != nil {
		t.Fatal(err)
	}
	if state.AppliedIP != "208.67.222.222" || updates(r) != 3 {
		t.Fatal("subsequent change did not use applied IP ownership")
	}
}

// The Azure CLI expands "@file" arguments, so values that came from Azure
// must never reach it in that form.
func TestAzureCLIRefusesFileExpansionArguments(t *testing.T) {
	e, r, _ := fixtureEngine(t, fixtureTarget("owned", "nsg"))
	a := e.Config.Actions["allow"]
	for _, args := range [][]string{{"--description", "@~/.ssh/id_ed25519"}, {"--tags", "key=@secrets.json"}} {
		if _, err := e.az(t.Context(), a, args); err == nil || !strings.Contains(err.Error(), "starts with @") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("refused arguments reached the CLI: %v", r.calls)
	}
	// An "@" elsewhere in a value is ordinary text and reaches the CLI.
	_, _ = e.az(t.Context(), a, []string{"--description", "owner: ops@example.com"})
	if len(r.calls) != 1 {
		t.Fatalf("ordinary argument was refused: %v", r.calls)
	}
}

// Azure names ignore case and create is an upsert: a case-variant rule must
// be treated as present so it is refused, never overwritten.
func TestRuleLookupIgnoresCase(t *testing.T) {
	target := fixtureTarget("owned", "nsg")
	if _, ok := findNSGRule(azureNSG{Rules: []azureRule{{Name: "Managed-IP"}}}, target); !ok {
		t.Fatal("case-variant NSG rule looked absent")
	}
	if _, ok := findPGRule([]azureRule{{Name: "NetShift-Rule"}}, "netshift-rule"); !ok {
		t.Fatal("case-variant PostgreSQL rule looked absent")
	}
}

// map must not learn ownership from another team's NSG that happens to use
// the same history tag elsewhere in the subscription.
func TestMapReadsHistoryOnlyFromManagedNSGs(t *testing.T) {
	owned := fixtureTarget("owned", "nsg")
	c := config.Config{Version: 1, Profile: "test", Actions: map[string]config.ActionConfig{"allow": {Type: "azure_allowlist", Targets: []config.Target{owned}, SharedIPHistory: &config.SharedIPHistoryConfig{}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	tag := c.Actions["allow"].SharedIPHistory.Tag
	theirs := "/subscriptions/" + owned.Subscription + "/resourceGroups/other/providers/Microsoft.Network/networkSecurityGroups/theirs"
	nsgs, _ := json.Marshal([]map[string]any{
		{"id": config.NSGResourceID(owned), "name": owned.NSG, "resourceGroup": owned.ResourceGroup, "tags": map[string]string{tag: `{"v":1,"ips":["8.8.8.8"]}`}},
		{"id": theirs, "name": "theirs", "resourceGroup": "other", "tags": map[string]string{tag: `{"v":1,"ips":["9.9.9.9"]}`}},
	})
	runner := runnerFunc(func(_ context.Context, _ string, args, _ []string) ([]byte, error) {
		if args[0] == "account" {
			return []byte(`{"name":"test","id":"` + owned.Subscription + `"}`), nil
		}
		return nsgs, nil
	})
	dir := t.TempDir()
	output := filepath.Join(dir, "map.json")
	var out bytes.Buffer
	if err := HandleMap(t.Context(), c, filepath.Join(dir, "state.json"), []string{"--output", output}, runner, &out); err != nil {
		t.Fatal(err)
	}
	// Command output goes to the writer the CLI passes, like every other command's.
	if !strings.HasPrefix(out.String(), "Mapped 2 NSGs") {
		t.Fatalf("summary not written to command output: %q", out.String())
	}
	var m azureMapping
	data, _ := os.ReadFile(output)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.KnownIPs, "8.8.8.8") || slices.Contains(m.KnownIPs, "9.9.9.9") {
		t.Fatalf("known IPs = %v", m.KnownIPs)
	}
}

// Migration converts an existing shared-history tag into a marker, but adds
// no marker tag where shared history never existed: that would only spend
// one of the NSG's 50 tag slots.
func TestPerMachineMigrationMarksOnlyExistingSharedHistory(t *testing.T) {
	nsg, pg := fixtureTarget("one", "nsg"), fixtureTarget("db", "postgres")
	var rule azureRule
	raw, _ := json.Marshal(fixtureRule(nsg, "8.8.8.8"))
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatal(err)
	}
	prepare := func(shared bool, tags map[string]string) *config.DevicesConfig {
		t.Helper()
		e, _, _ := fixtureEngine(t, nsg, pg)
		if shared {
			enableShared(t, e, &fakeRunner{})
		}
		e.Config.Identity = "sam@laptop"
		inventory := []azureNSG{{ID: config.NSGResourceID(nsg), Name: nsg.NSG, Tags: tags, Rules: []azureRule{rule}}}
		next, err := prepareDeviceConfig(e.Config, "allow", inventory)
		if err != nil {
			t.Fatal(err)
		}
		return next.Actions["allow"].Devices
	}
	if d := prepare(false, map[string]string{"comment": "human"}); d.LegacyTag != "" || d.LegacyIdentity != "sam@laptop" {
		t.Fatalf("no shared history: %+v", d)
	}
	if d := prepare(false, map[string]string{"NetShift.Test.IP-History": cachedJSON("8.8.8.8")}); d.LegacyTag != "netshift.test.ip-history" {
		t.Fatalf("existing history tag: %+v", d)
	}
	if d := prepare(true, nil); d.LegacyTag != "netshift.test.ip-history" || d.LegacyIdentity != "sam@laptop" {
		t.Fatalf("configured shared history: %+v", d)
	}
}

// Mapped rules report removals of addresses this identity did not place.
func TestMappedRuleLogsRemovalOfAnAddressItDidNotPlace(t *testing.T) {
	e, r, _ := mappedFixture(t, []string{"8.8.8.8", "1.1.1.1"})
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	e.History = nil
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	unplaced := func() []any {
		var ips []any
		for line := range strings.Lines(log.String()) {
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatal(err)
			}
			if event["event"] == "unplaced_address_removed" {
				ips = append(ips, event["ips"])
			}
		}
		log.Reset()
		return ips
	}
	if err := e.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(unplaced()); got != "[[8.8.8.8]]" {
		t.Fatalf("first replacement has no verified record: %s", got)
	}
	if err := e.step(context.Background(), confirmed("1.0.0.1"), true, true); err != nil {
		t.Fatal(err)
	}
	if got := unplaced(); len(got) != 0 {
		t.Fatalf("replacing its own verified address was reported: %v", got)
	}
	r.rules["shared"]["sourceAddressPrefixes"] = []string{"1.0.0.1/32", "1.1.1.1", "9.9.9.9"}
	if err := e.step(context.Background(), confirmed("1.0.0.1"), false, true); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(unplaced()); got != "[[9.9.9.9]]" {
		t.Fatalf("re-added address: %s", got)
	}
	if !reflect.DeepEqual(r.rules["shared"]["sourceAddressPrefixes"], []string{"1.0.0.1/32", "1.1.1.1"}) {
		t.Fatalf("removal changed: %v", r.rules["shared"]["sourceAddressPrefixes"])
	}
}
