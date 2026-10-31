package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
)

// registryNSG is the fake NSG that holds target i's rule.
func registryNSG(f *deviceCloud, a config.ActionConfig, i int) *azureNSG {
	return f.nsgs[strings.ToLower(config.NSGResourceID(a.Targets[i]))]
}

// historyRows reads e's whole local audit history.
func historyRows(t *testing.T, e *Engine) []store.HistoryRecord {
	t.Helper()
	rows, err := store.ReadHistory(store.HistoryPath(e.StatePath), 100000, "")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// logEvents decodes a Logger's output, one JSON object per line.
func logEvents(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var events []map[string]any
	for line := range strings.Lines(out.String()) {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

// twoMachines enrolls sam@laptop at 8.8.4.4 and sam@desktop at 1.1.1.1.
func twoMachines(t *testing.T) (*Engine, *Engine, *deviceCloud, config.ActionConfig) {
	t.Helper()
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "1.1.1.1")
	return e, home, f, e.Config.Actions["allow"]
}

// A rule deleted out of band must not block retirement: there is nothing left
// to remove from it, and the database rule must still be revoked.
func TestRetirementRevokesDatabaseWhenAnNSGRuleIsMissing(t *testing.T) {
	e, _, f, a := twoMachines(t)
	registryNSG(f, a, 0).Rules = nil
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], "sam@desktop")
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived retirement")
	}
	if len(registryNSG(f, a, 0).Rules) != 0 {
		t.Fatal("retirement recreated a missing rule")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	for _, n := range f.nsgs {
		if _, ok := n.Tags[deviceTag(a, "sam@desktop", false)]; ok {
			t.Fatal("active record kept after a complete retirement")
		}
	}
}

// One failing target must not stop the others, and the active record stays
// until every target has been cleaned up.
func TestRetirementVisitsEveryTargetBeforeReportingFailure(t *testing.T) {
	e, _, f, a := twoMachines(t)
	registryNSG(f, a, 0).Rules[0].Priority = 4000 // shape changed: needs inspection
	err := e.retireDevice(context.Background(), "allow", a, "sam@desktop")
	if err == nil || !strings.Contains(err.Error(), "review mapping") {
		t.Fatalf("expected the changed rule to be reported, got %v", err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], "sam@desktop")
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived a failure on an earlier target")
	}
	if slices.Contains(registryNSG(f, a, 1).Rules[0].Sources, "1.1.1.1/32") {
		t.Fatal("later NSG target was not cleaned up")
	}
	for _, n := range f.nsgs {
		if _, ok := n.Tags[deviceTag(a, "sam@desktop", false)]; !ok {
			t.Fatal("active record deleted although a target still holds access")
		}
	}
}

// Another identity's record that this version cannot use is skipped and never
// acted on: retirement proceeds, the record is untouched, and an address it
// mentions is neither removed nor added. When that address is the retired
// identity's own, retirement still revokes everything else but does not
// report success while the address stays allowed: it logs
// retired_address_retained, fails, and keeps the active record, and a retry
// completes once the record is fixed.
func TestRetirementSkipsOtherIdentitiesUnusableRecords(t *testing.T) {
	e, _, f, a := twoMachines(t)
	leeKey := deviceTag(a, "lee@laptop", false)
	newer := `{"v":3,"id":"lee@laptop","ips":["1.1.1.1"],"r":1}`
	garbage := deviceTag(a, "kim@laptop", false)
	for _, n := range f.nsgs {
		n.Tags[leeKey] = newer
		n.Tags[garbage] = "not json"
	}
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("ordinary reconciliation accepted an unusable registry")
	}
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	err := e.retireDevice(context.Background(), "allow", a, "sam@desktop")
	if err == nil || !strings.Contains(err.Error(), "[1.1.1.1] stays allowed") {
		t.Fatalf("retirement that left 1.1.1.1 allowed reported %v", err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], "sam@desktop")
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived retirement")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4", "1.1.1.1")
	for _, n := range f.nsgs {
		if n.Tags[leeKey] != newer || n.Tags[garbage] != "not json" {
			t.Fatal("retirement changed another identity's record")
		}
		if _, ok := n.Tags[deviceTag(a, "sam@desktop", false)]; !ok {
			t.Fatal("active record dropped although a retired address stays allowed")
		}
	}
	skipped, retained := 0, ""
	for _, event := range logEvents(t, &log) {
		switch event["event"] {
		case "device_record_skipped":
			skipped++
		case "retired_address_retained":
			retained = fmt.Sprint(event["identity"], event["ips"])
		}
	}
	if skipped == 0 {
		t.Fatal("skipped records were not logged")
	}
	if retained != "sam@desktop[1.1.1.1]" {
		t.Fatalf("retained address not logged: %q", retained)
	}
	for _, n := range f.nsgs {
		delete(n.Tags, leeKey)
	}
	if err = e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	// The retiring identity's own records are never skipped.
	for _, n := range f.nsgs {
		n.Tags[deviceTag(a, "sam@laptop", true)] = "not json"
	}
	if e.retireDevice(context.Background(), "allow", a, "sam@laptop") == nil {
		t.Fatal("retired an identity whose own marker is unusable")
	}
}

// Enrollment leaves one tag slot free, so a retirement marker always fits.
func TestEnrollmentKeepsATagSlotForRetirement(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	for _, n := range f.nsgs {
		for i := 0; len(n.Tags) < 49; i++ {
			n.Tags[fmt.Sprintf("team-%02d", i)] = "keep"
		}
	}
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	home.State.IP = "1.1.1.1"
	err := home.runDevices(context.Background(), "allow", a, home.State.IP, true)
	if err == nil || !strings.Contains(err.Error(), "retirement marker") {
		t.Fatalf("enrollment at 49 tags: %v", err)
	}
	if f.writes["tag:"+deviceTag(a, "sam@desktop", false)] != 0 {
		t.Fatal("refused enrollment wrote a tag")
	}
	for _, n := range f.nsgs {
		delete(n.Tags, "team-00")
	}
	driveDevice(t, home, "1.1.1.1")
	if err = e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		if _, ok := n.Tags[deviceTag(a, "sam@desktop", true)]; !ok || len(n.Tags) > 50 {
			t.Fatalf("%s: marker missing or tag limit exceeded (%d tags)", n.Name, len(n.Tags))
		}
	}
}

// A watcher that planned before the marker existed can still land a new
// address. The marker is extended before cleanup, so that address is neither
// stranded in a rule nor forgotten when the active record is dropped.
func TestRetirementExtendsTheMarkerForARacingActiveWrite(t *testing.T) {
	e, _, f, a := twoMachines(t)
	activeKey, retiredKey := deviceTag(a, "sam@desktop", false), deviceTag(a, "sam@desktop", true)
	raced := false
	f.afterWrite = func(key string) {
		if raced || key != "tag:"+retiredKey {
			return
		}
		raced = true
		for _, n := range f.nsgs {
			d, err := parseDevice(n.Tags[activeKey])
			if err != nil {
				t.Fatal(err)
			}
			d.IPs, d.Revision = append([]string{"4.2.2.2"}, d.IPs...), d.Revision+1
			raw, err := encodeDevice(d, 10)
			if err != nil {
				t.Fatal(err)
			}
			n.Tags[activeKey] = raw
			n.Rules[0].Sources = append(n.Rules[0].Sources, "4.2.2.2/32")
		}
	}
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	if !raced {
		t.Fatal("the race was not injected")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	for _, n := range f.nsgs {
		marker, err := parseDevice(n.Tags[retiredKey])
		if err != nil || !containsAll(marker.IPs, []string{"4.2.2.2", "1.1.1.1"}) {
			t.Fatalf("marker does not cover the raced address: %+v %v", marker, err)
		}
		if _, ok := n.Tags[activeKey]; ok {
			t.Fatal("active record kept")
		}
	}
}

// The active record is dropped only while the marker lists all of its
// addresses; a later write makes retirement stop, and a retry completes it.
func TestRetirementRefusesToDropAnUncoveredActiveRecord(t *testing.T) {
	e, _, f, a := twoMachines(t)
	activeKey, retiredKey := deviceTag(a, "sam@desktop", false), deviceTag(a, "sam@desktop", true)
	own := devicePGTarget(e.Config, a.Targets[2], "sam@desktop")
	f.afterWrite = func(key string) {
		if key != "pg:delete:database:"+own.Rule {
			return
		}
		for _, n := range f.nsgs {
			d, _ := parseDevice(n.Tags[activeKey])
			d.IPs, d.Revision = append([]string{"208.67.222.222"}, d.IPs...), d.Revision+1
			raw, _ := encodeDevice(d, 10)
			n.Tags[activeKey] = raw
		}
	}
	err := e.retireDevice(context.Background(), "allow", a, "sam@desktop")
	if err == nil || !strings.Contains(err.Error(), "lacks") {
		t.Fatalf("dropped an active record the marker does not cover: %v", err)
	}
	for _, n := range f.nsgs {
		if _, ok := n.Tags[activeKey]; !ok {
			t.Fatal("active record dropped")
		}
	}
	f.afterWrite = nil
	if err = e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		marker, _ := parseDevice(n.Tags[retiredKey])
		if !slices.Contains(marker.IPs, "208.67.222.222") {
			t.Fatal("retry did not extend the marker")
		}
	}
}

// PostgreSQL rule names include the profile, so every machine sharing a
// registry must derive them from the same profile name.
func TestDeviceTagPrefixMustNameTheProfile(t *testing.T) {
	e, _ := deviceFixture(t)
	for prefix, valid := range map[string]bool{
		"netshift.test.device.":    true,
		"netshift.Test.machines.":  true,
		"netshift.shared.device.":  false,
		"netshift.testing.device.": false,
	} {
		c := e.Config
		a := c.Actions["allow"]
		d := *a.Devices
		d.TagPrefix = prefix
		a.Devices = &d
		c.Actions = map[string]config.ActionConfig{"allow": a}
		if err := c.Validate(); (err == nil) != valid {
			t.Errorf("%s: valid=%v, got %v", prefix, valid, err)
		}
	}
}

// A create that failed definitively leaves an intent, but absence satisfies
// it during retirement. If the create lands late after all, its stable name
// lets the next cleanup of the retired identity remove it.
func TestRetirementSupersedesAFailedPostgresCreate(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
	f.reject = "pg:create:database:" + own.Rule
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); err == nil {
		t.Fatal("expected the create to fail")
	}
	slot := expectedResourceID(own) + "#"
	pending := e.pendingWrite("allow", slot)
	if pending == nil || pending.Status != statusDeviceCreateIntent {
		t.Fatalf("pending create: %+v", pending)
	}
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	if e.pendingWrite("allow", slot) != nil {
		t.Fatal("failed create still pending")
	}
	if !slices.ContainsFunc(historyRows(t, e), func(r store.HistoryRecord) bool {
		return r.Status == statusDeviceSuperseded && r.OperationID == pending.OperationID
	}) {
		t.Fatal("superseded create missing from history")
	}
	raw, _ := json.Marshal(fixtureRule(own, "8.8.4.4"))
	var late azureRule
	_ = json.Unmarshal(raw, &late)
	f.pg[own.Server][own.Rule] = late
	if err := e.runDevices(context.Background(), "allow", a, e.State.IP, false); !errors.Is(err, errIdentityRetired) {
		t.Fatal(err)
	}
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("late create survived retirement")
	}
}

// Enrolling an identity that is retired in the cloud reports that instead of
// exiting 0; watch treats the same discovery as the end of its work.
func TestEnrollingARetiredIdentityReportsIt(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	peer := deviceEngine(t, e.Config, f, "sam@desktop")
	if err := peer.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	reinstalled := deviceEngine(t, e.Config, f, e.Config.Identity)
	reinstalled.State.IP = "8.8.4.4"
	err := reinstalled.runDevices(context.Background(), "allow", a, "8.8.4.4", true)
	if !errors.Is(err, errIdentityRetired) || err.Error() != "identity is retired; use devices activate" {
		t.Fatalf("enroll of a retired identity: %v", err)
	}
	if !reinstalled.State.Action("allow").Retired {
		t.Fatal("retirement not recorded locally")
	}

	watcher := deviceEngine(t, e.Config, f, e.Config.Identity)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	watcher.Now = func() time.Time { return now }
	watcher.Config.Notifications = &config.NotificationConfig{Enabled: true, AfterFailures: 1, CooldownSeconds: 30}
	watcher.Notify = func(context.Context, string, string) error { t.Fatal("retirement sent a notification"); return nil }
	if err := watcher.step(context.Background(), confirmed("8.8.4.4"), true, true); err != nil {
		t.Fatal(err)
	}
	s := watcher.State.Action("allow")
	if !s.Retired || s.Attempts != 0 || !s.RetryAt.IsZero() || s.LastError != "" || s.Notice != nil {
		t.Fatalf("watch treated retirement as a failure: %+v", s)
	}
}

// longIdentity is the longest canonical identity: a 32-character user and a
// 63-character host. Its records hold the fewest addresses.
func longIdentity(host string) string {
	return "sam_" + strings.Repeat("x", 28) + "@" + host + strings.Repeat("h", 63-len(host))
}

// Any active record can be re-encoded as its retirement marker, at the next
// revision, without losing an address: active records are budgeted as one.
func TestActiveRecordAlwaysFitsItsRetirementMarker(t *testing.T) {
	var ips []string
	for i := range 10 {
		ips = append(ips, fmt.Sprintf("208.67.222.%d", 240+i))
	}
	for hostLen := 1; hostLen <= 63; hostLen++ {
		for _, user := range []string{"sam", "sam_" + strings.Repeat("x", 28)} {
			id := user + "@" + strings.Repeat("h", hostLen)
			for _, revision := range []uint64{1, 9, 99, 999_999, math.MaxUint64 - 1} {
				raw, err := encodeDevice(DeviceRecord{Version: 2, Identity: id, IPs: ips, Revision: revision}, 10)
				if err != nil {
					t.Fatal(err)
				}
				d, err := parseDevice(raw)
				if err != nil {
					t.Fatal(err)
				}
				marker := d
				marker.Retired, marker.Revision = true, d.Revision+1
				b, err := json.Marshal(marker)
				if err != nil {
					t.Fatal(err)
				}
				if len(b) > maxTagValue {
					t.Fatalf("%s at revision %d: record of %d addresses is %d bytes as a marker", id, revision, len(d.IPs), len(b))
				}
			}
		}
	}
}

// A long identity whose record is full still retires completely, so its
// database access is revoked and its active record removed.
func TestLongIdentityWithFullHistoryRetires(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	long := longIdentity("build-")
	device := deviceEngine(t, e.Config, f, long)
	for i := range 7 {
		driveDevice(t, device, fmt.Sprintf("208.67.222.%d", 100+i))
	}
	a := e.Config.Actions["allow"]
	retirer := deviceEngine(t, e.Config, f, strings.Split(long, "@")[0]+"@desktop")
	if err := retirer.retireDevice(context.Background(), "allow", a, long); err != nil {
		t.Fatal(err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], long)
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived retirement")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	for _, n := range f.nsgs {
		if _, ok := n.Tags[deviceTag(a, long, false)]; ok {
			t.Fatal("active record kept after a complete retirement")
		}
	}
}

// An active record can list more addresses than its retirement marker
// holds. Retirement still revokes all access,
// keeps the active record so no address is forgotten, and reports that. A
// dry run reports the same gap from the registry, and writes nothing.
func TestOversizedOldRecordStillLosesAccessOnRetirement(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	long := longIdentity("old-")
	device := deviceEngine(t, e.Config, f, long)
	driveDevice(t, device, "208.67.222.106")
	a := e.Config.Actions["allow"]
	activeKey, retiredKey := deviceTag(a, long, false), deviceTag(a, long, true)
	old := DeviceRecord{Version: 2, Identity: long, Revision: 2, IPs: []string{"208.67.222.106", "208.67.222.105", "208.67.222.104", "208.67.222.103", "208.67.222.102", "208.67.222.101", "208.67.222.100"}}
	raw, _ := json.Marshal(old)
	if _, err := parseDevice(string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		n.Tags[activeKey] = string(raw)
	}
	retirer := deviceEngine(t, e.Config, f, strings.Split(long, "@")[0]+"@desktop")
	var log bytes.Buffer
	retirer.Log = eventlog.Logger{Out: &log}
	retirer.Apply = false
	writes := fmt.Sprint(f.writes)
	err := retirer.retireDevice(context.Background(), "allow", a, long)
	if !errors.Is(err, errMarkerIncomplete) || !strings.Contains(err.Error(), "208.67.222.100") {
		t.Fatalf("dry run: %v", err)
	}
	if fmt.Sprint(f.writes) != writes {
		t.Fatal("dry run wrote")
	}
	if !slices.ContainsFunc(logEvents(t, &log), func(event map[string]any) bool { return event["event"] == "would_delete_device_postgres_rule" }) {
		t.Fatal("dry run did not preview cleanup")
	}
	retirer.Apply = true
	if err = retirer.retireDevice(context.Background(), "allow", a, long); !errors.Is(err, errMarkerIncomplete) {
		t.Fatalf("retirement with an oversized record: %v", err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], long)
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived retirement")
	}
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4")
	for _, n := range f.nsgs {
		if n.Tags[activeKey] != string(raw) {
			t.Fatal("active record changed although the marker cannot list it")
		}
		if marker, err := parseDevice(n.Tags[retiredKey]); err != nil || !marker.Retired {
			t.Fatalf("marker: %+v %v", marker, err)
		}
	}
	// The identity stays retired for every reader.
	reg, err := e.loadDevices(context.Background(), a)
	if err != nil || !reg.Devices[long].Retired {
		t.Fatalf("registry after incomplete retirement: %v", err)
	}
}

// A dry run of retirement previews every change, including the marker and
// the removal of the active record, writes nothing, and succeeds.
func TestRetirementDryRunPreviewsWithoutWriting(t *testing.T) {
	e, _, f, a := twoMachines(t)
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	e.Apply = false
	writes := fmt.Sprint(f.writes)
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.writes) != writes {
		t.Fatal("dry run wrote")
	}
	var previews []string
	for _, event := range logEvents(t, &log) {
		switch event["event"] {
		case "would_update_device_tag":
			previews = append(previews, fmt.Sprint(event["nsg"], " ", event["after"] != ""))
		case "would_reconcile_device_sources":
			if event["unplaced_removals"] != nil {
				t.Fatalf("retirement previewed an unplaced removal: %v", event)
			}
			previews = append(previews, fmt.Sprint(event["target"], " ", event["retired_removals"]))
		case "would_delete_device_postgres_rule":
			previews = append(previews, "database")
		}
	}
	// The marker on both NSGs, both rules, the database rule, then the
	// active record on both NSGs.
	want := "[one true two true one [1.1.1.1] two [1.1.1.1] database one false two false]"
	if fmt.Sprint(previews) != want {
		t.Fatalf("previews %v, want %s", previews, want)
	}
}

// The legacy migration marker, like a device record, must leave the last tag
// slot free for a retirement marker; a refused enrollment writes nothing.
func TestLegacyMarkerKeepsTheRetirementSlot(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	two := registryNSG(f, a, 1)
	delete(two.Tags, "netshift.test.ip-history")
	for i := 0; len(two.Tags) < 48; i++ {
		two.Tags[fmt.Sprintf("team-%02d", i)] = "keep"
	}
	e.State.IP = "8.8.4.4"
	err := e.runDevices(context.Background(), "allow", a, e.State.IP, true)
	if err == nil || !strings.Contains(err.Error(), "retirement marker") {
		t.Fatalf("enrollment that fills the last tag slot: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("refused enrollment wrote: %v", f.writes)
	}
	delete(two.Tags, "team-00")
	driveDevice(t, e, "8.8.4.4")
	if err = e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
	if _, ok := f.pg[own.Server][own.Rule]; ok {
		t.Fatal("database access survived retirement")
	}
	if _, ok := two.Tags[deviceTag(a, e.Config.Identity, true)]; !ok || len(two.Tags) > maxNSGTags {
		t.Fatalf("marker missing or tag limit exceeded (%d tags)", len(two.Tags))
	}
}

// Removing the retired identity's own addresses is logged as retirement,
// not as the removal of an address the retirer did not place.
func TestRetirementLogsTheRetiredAddressesItRemoves(t *testing.T) {
	e, _, _, a := twoMachines(t)
	var log bytes.Buffer
	e.Log = eventlog.Logger{Out: &log}
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	var retired []string
	for _, event := range logEvents(t, &log) {
		switch event["event"] {
		case "unplaced_address_removed":
			t.Fatalf("retirement logged an unplaced removal: %v", event)
		case "retired_address_removed":
			retired = append(retired, fmt.Sprint(event["target"], event["identity"], event["ips"]))
		}
	}
	if fmt.Sprint(retired) != "[onesam@desktop[1.1.1.1] twosam@desktop[1.1.1.1]]" {
		t.Fatalf("retired removals %v", retired)
	}
}

// Two retirers that planned from one read can leave different markers at
// one revision on different NSGs. Markers only grow, so they merge instead
// of wedging the registry, and a retry writes the union everywhere. Two
// different active records at one revision still conflict.
func TestSameRevisionMarkersMerge(t *testing.T) {
	e, _, f, a := twoMachines(t)
	activeKey, retiredKey := deviceTag(a, "sam@desktop", false), deviceTag(a, "sam@desktop", true)
	active, err := parseDevice(registryNSG(f, a, 0).Tags[activeKey])
	if err != nil {
		t.Fatal(err)
	}
	for i, ips := range [][]string{{"1.1.1.1"}, {"1.1.1.1", "4.2.2.2"}} {
		raw, err := encodeDevice(DeviceRecord{Version: 2, Identity: "sam@desktop", IPs: ips, Revision: active.Revision + 1, Retired: true}, 10)
		if err != nil {
			t.Fatal(err)
		}
		registryNSG(f, a, i).Tags[retiredKey] = raw
	}
	reg, err := e.loadDevices(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if got := reg.Devices["sam@desktop"]; !got.Retired || !slices.Equal(got.IPs, []string{"1.1.1.1", "4.2.2.2"}) {
		t.Fatalf("merged marker %+v", got)
	}
	driveDevice(t, e, "8.8.4.4")
	if err = e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	for _, n := range f.nsgs {
		marker, err := parseDevice(n.Tags[retiredKey])
		if err != nil || !containsAll(marker.IPs, []string{"1.1.1.1", "4.2.2.2"}) {
			t.Fatalf("%s marker %+v %v", n.Name, marker, err)
		}
		if _, ok := n.Tags[activeKey]; ok {
			t.Fatal("active record kept")
		}
	}
	conflict := newRegistry()
	if err = conflict.merge(active); err != nil {
		t.Fatal(err)
	}
	other := active
	other.IPs = []string{"4.2.2.2"}
	if !errors.Is(conflict.merge(other), errRegistryConflict) {
		t.Fatal("same-revision active records merged")
	}
}

// Command-line mistakes in devices are usage errors (exit status 2), found
// before any state or Azure access.
func TestDevicesCommandUsageErrors(t *testing.T) {
	e, _ := deviceFixture(t)
	two := e.Config
	two.Actions = map[string]config.ActionConfig{"first": e.Config.Actions["allow"], "second": e.Config.Actions["allow"]}
	statePath := filepath.Join(t.TempDir(), "missing", "state.json")
	for _, c := range []struct {
		config config.Config
		args   []string
	}{
		{two, []string{"list"}},
		{e.Config, []string{"list", "--action", "nope"}},
		{e.Config, []string{"list", "--apply"}},
	} {
		if err := HandleDevices(context.Background(), c.config, statePath, c.args, io.Discard, eventlog.Logger{Out: io.Discard}); !errors.Is(err, cmdline.ErrUsage) {
			t.Errorf("%q: %v is not a usage error", c.args, err)
		}
	}
}

// devices list prints the registry to command output.
func TestDevicesListWritesCommandOutput(t *testing.T) {
	e, f := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	dir := t.TempDir()
	for _, n := range f.nsgs {
		raw, _ := json.Marshal(n)
		if err := os.WriteFile(filepath.Join(dir, n.Name+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A stand-in Azure CLI that prints the NSG named by --name. On Windows
	// it is a batch file that passes its arguments on with %*, as the Azure
	// CLI's az.cmd does, to this test binary (see TestMain).
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --name ]; then exec cat '" + dir + "'/\"$2\".json; fi; shift; done; exit 1\n"
	cli := filepath.Join(dir, "az")
	if runtime.GOOS == "windows" {
		script = "@\"%NETSHIFT_TEST_BINARY%\" %*\r\n"
		cli += ".cmd"
		t.Setenv("NETSHIFT_TEST_BINARY", os.Args[0])
		t.Setenv(fakeAzureEnv, dir)
	}
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	c := e.Config
	a := c.Actions["allow"]
	a.AzureCLI = cli
	c.Actions = map[string]config.ActionConfig{"allow": a}
	var out bytes.Buffer
	if err := HandleDevices(context.Background(), c, e.StatePath, []string{"list"}, &out, eventlog.Logger{Out: io.Discard}); err != nil {
		t.Fatal(err)
	}
	var listed map[string]DeviceRecord
	if err := json.Unmarshal(out.Bytes(), &listed); err != nil || listed[e.Config.Identity].IPs[0] != "8.8.4.4" {
		t.Fatalf("listed %q: %v", out.String(), err)
	}
}
