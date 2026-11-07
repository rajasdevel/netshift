package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/rajasdevel/netshift/internal/config"
)

// docCluster is a fake DocumentDB cluster's firewall rules, as ARM documents.
// A write leaves a rule InProgress (or Dropping) for lag reads, like Azure's
// long-running operations; paged makes the list report a next page.
type docCluster struct {
	rules map[string]*docRule
	lag   int
	paged bool
	fail  bool
}

type docRule struct {
	doc      map[string]any
	pending  int
	deleting bool
}

// advance moves every rule's pending operation one read closer to done.
func (c *docCluster) advance() {
	for name, r := range c.rules {
		if r.pending > 0 {
			r.pending--
			continue
		}
		if r.deleting {
			delete(c.rules, name)
		} else if p := r.doc["properties"].(map[string]any); p["provisioningState"] == "InProgress" {
			p["provisioningState"] = "Succeeded"
			if c.fail {
				p["provisioningState"] = "Failed"
			}
		}
	}
}

// rest serves az rest requests for DocumentDB firewall rules.
func (f *deviceCloud) rest(args []string) ([]byte, error) {
	url, query, _ := strings.Cut(argValue(args, "--url"), "?")
	if query != "api-version=2025-09-01" {
		return nil, errors.New("unexpected api-version")
	}
	clusterID, rule, _ := strings.Cut(url, "/firewallRules")
	c := f.docdb[strings.ToLower(clusterID)]
	if c == nil {
		return nil, errors.New("(ResourceNotFound) cluster")
	}
	rule = strings.TrimPrefix(rule, "/")
	method := argValue(args, "--method")
	if rule == "" {
		if method != "get" {
			return nil, errors.New("unexpected collection method")
		}
		c.advance()
		page := map[string]any{"value": []any{}}
		for _, r := range c.rules {
			page["value"] = append(page["value"].([]any), r.doc)
		}
		if c.paged {
			page["nextLink"] = "https://management.azure.com" + url + "?$skipToken=x"
		}
		return json.Marshal(page)
	}
	stored, found := foldKey(c.rules, rule)
	switch method {
	case "get":
		c.advance()
		if r := c.rules[stored]; r != nil {
			return json.Marshal(r.doc)
		}
		return nil, errors.New("(ResourceNotFound) rule")
	case "put":
		key := "docdb:put:" + rule
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		var body struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal([]byte(argValue(args, "--body")), &body); err != nil {
			return nil, err
		}
		body.Properties["provisioningState"] = "InProgress"
		r := &docRule{pending: c.lag, doc: map[string]any{"id": url, "name": rule, "type": "Microsoft.DocumentDB/mongoClusters/firewallRules", "systemData": map[string]any{"lastModifiedAt": "now"}, "properties": body.Properties}}
		if found {
			// PUT replaces the rule in place, keeping its stored name.
			r.doc["id"], r.doc["name"] = c.rules[stored].doc["id"], stored
		}
		c.rules[stored] = r
		if err := f.wrote(key); err != nil {
			return nil, err
		}
		return json.Marshal(r.doc)
	case "delete":
		key := "docdb:delete:" + rule
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		if found {
			c.rules[stored].pending, c.rules[stored].deleting = c.lag, true
			c.rules[stored].doc["properties"].(map[string]any)["provisioningState"] = "Dropping"
		}
		return nil, f.wrote(key)
	}
	return nil, errors.New("unexpected method " + method)
}

// ipListRes is a fake storage account's or key vault's network rules, with
// the Azure CLI's behavior: add skips an address that an entry already
// covers, remove drops every entry of the same network, and a key vault
// stores single addresses as /32.
type ipListRes struct {
	entries []string
	other   map[string]any // the rest of the network rule set
	id      string
	tags    map[string]string
}

func (f *deviceCloud) ipList(args []string) ([]byte, error) {
	kind, verb, name := args[0], args[2], argValue(args, "--name")
	switch {
	case kind == "keyvault" && args[1] == "show":
		verb = "show"
	case kind == "storage" && args[2] == "show":
		verb = "show"
	case kind == "storage":
		verb, name = args[3], argValue(args, "--account-name")
	}
	l := f.lists[strings.ToLower(kind+":"+name)]
	if l == nil {
		return nil, errors.New("(ResourceNotFound) " + name)
	}
	network := func(s string) netip.Prefix {
		if p, err := netip.ParsePrefix(s); err == nil {
			return p.Masked()
		}
		return netip.PrefixFrom(netip.MustParseAddr(s), 32)
	}
	switch verb {
	case "show":
		if l.other == nil {
			return json.Marshal(map[string]any{"id": l.id, "name": name, "tags": l.tags, "network": nil})
		}
		doc := map[string]any{}
		for k, v := range l.other {
			doc[k] = v
		}
		rules := []map[string]string{}
		for _, e := range l.entries {
			if kind == "storage" {
				rules = append(rules, map[string]string{"ipAddressOrRange": e, "action": "Allow"})
			} else {
				rules = append(rules, map[string]string{"value": e})
			}
		}
		doc["ipRules"] = rules
		return json.Marshal(map[string]any{"id": l.id, "name": name, "tags": l.tags, "network": doc})
	case "add":
		key := kind + ":add:" + name
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		for _, ip := range argValues(args, "--ip-address") {
			if slices.ContainsFunc(l.entries, func(e string) bool { return network(e).Overlaps(network(ip)) }) {
				continue
			}
			if kind == "keyvault" && !strings.Contains(ip, "/") {
				ip += "/32"
			}
			l.entries = append(l.entries, ip)
		}
		return []byte(`{}`), f.wrote(key)
	case "remove":
		key := kind + ":remove:" + name
		if err := f.rejected(key); err != nil {
			return nil, err
		}
		for _, ip := range argValues(args, "--ip-address") {
			l.entries = slices.DeleteFunc(l.entries, func(e string) bool { return network(e) == network(ip) })
		}
		return []byte(`{}`), f.wrote(key)
	}
	return nil, errors.New("unexpected list verb " + verb)
}

// allowlistFixture is deviceFixture plus a DocumentDB cluster with someone
// else's rule, a storage account, and a key vault. Both lists start with an
// unrelated address, a range, and 8.8.8.8 from sam@laptop's legacy history.
func allowlistFixture(t *testing.T) (*Engine, *deviceCloud) {
	t.Helper()
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	base := config.Target{Subscription: "00000000-0000-0000-0000-000000000001", ResourceGroup: "test-group"}
	doc, storage, vault := base, base, base
	doc.ID, doc.Kind, doc.Server = "cluster", config.KindDocumentDB, "cluster-one"
	storage.ID, storage.Kind, storage.Resource = "files", config.KindStorage, "filesaccount"
	vault.ID, vault.Kind, vault.Resource = "secrets", config.KindKeyVault, "secrets-vault"
	a.Targets = append(a.Targets, doc, storage, vault)
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	other := doc
	other.Rule = "someone-else"
	f.docdb = map[string]*docCluster{strings.ToLower(strings.TrimSuffix(expectedResourceID(doc), "/firewallRules/")): {rules: map[string]*docRule{
		other.Rule: {doc: map[string]any{"id": expectedResourceID(other), "name": other.Rule, "properties": map[string]any{"provisioningState": "Succeeded", "startIpAddress": "4.4.4.4", "endIpAddress": "4.4.4.4"}}},
	}}}
	f.lists = map[string]*ipListRes{
		"storage:filesaccount":   {id: expectedResourceID(storage), tags: map[string]string{"owner": "data team"}, entries: []string{"9.9.9.9", "4.2.2.0/24", "8.8.8.8"}, other: map[string]any{"defaultAction": "Deny", "bypass": "AzureServices", "virtualNetworkRules": []any{}, "resourceAccessRules": []any{}}},
		"keyvault:secrets-vault": {id: expectedResourceID(vault), entries: []string{"9.9.9.9/32", "4.2.2.0/24", "8.8.8.8/32"}, other: map[string]any{"defaultAction": "Deny", "bypass": "AzureServices", "virtualNetworkRules": []any{}}},
	}
	return deviceEngine(t, e.Config, f, e.Config.Identity), f
}

// cluster returns the fixture's DocumentDB cluster.
func (f *deviceCloud) cluster() *docCluster {
	for _, c := range f.docdb {
		return c
	}
	return nil
}

// docIPs returns each DocumentDB rule's address, by rule name.
func (f *deviceCloud) docIPs(t *testing.T) map[string]string {
	t.Helper()
	got := map[string]string{}
	for name, r := range f.cluster().rules {
		p := r.doc["properties"].(map[string]any)
		if p["startIpAddress"] != p["endIpAddress"] {
			t.Fatalf("%s is a range", name)
		}
		got[name] = p["startIpAddress"].(string)
	}
	return got
}

func assertList(t *testing.T, f *deviceCloud, key string, want ...string) {
	t.Helper()
	if got := f.lists[key].entries; !sameStrings(got, want) {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

func TestDocumentDBRulesFollowEachIdentity(t *testing.T) {
	e, f := allowlistFixture(t)
	a := e.Config.Actions["allow"]
	doc := a.Targets[3]
	laptop := deviceRuleTarget(e.Config, doc, "sam@laptop").Rule
	desktop := deviceRuleTarget(e.Config, doc, "sam@desktop").Rule
	if len(laptop) > 80 {
		t.Fatal("rule name too long for DocumentDB:", laptop)
	}
	driveDevice(t, e, "8.8.4.4")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "1.1.1.1")
	driveDevice(t, e, "208.67.222.222")
	want := map[string]string{"someone-else": "4.4.4.4", laptop: "208.67.222.222", desktop: "1.1.1.1"}
	if got := f.docIPs(t); !mapsEqual(got, want) {
		t.Fatal(got)
	}
	if f.writes["docdb:put:"+laptop] != 2 || f.writes["docdb:put:"+desktop] != 1 {
		t.Fatal("rules were not created once and then updated in place:", f.writes)
	}
	writes := len(f.writes)
	driveDevice(t, e, "208.67.222.222")
	if len(f.writes) != writes {
		t.Fatal("an unchanged address rewrote a rule")
	}
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	delete(want, desktop)
	if got := f.docIPs(t); !mapsEqual(got, want) {
		t.Fatal("retirement left", got)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestDocumentDBWaitsForAzureToFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, f := allowlistFixture(t)
		f.cluster().lag = 3
		driveDevice(t, e, "8.8.4.4")
		own := deviceRuleTarget(e.Config, e.Config.Actions["allow"].Targets[3], e.Config.Identity).Rule
		if f.cluster().rules[own].doc["properties"].(map[string]any)["provisioningState"] != "Succeeded" {
			t.Fatal("finished before Azure did")
		}
		if err := e.retireDevice(context.Background(), "allow", e.Config.Actions["allow"], "sam@laptop"); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.cluster().rules[own]; ok {
			t.Fatal("retirement finished while the rule was still dropping")
		}
	})
	synctest.Test(t, func(t *testing.T) {
		e, f := allowlistFixture(t)
		f.cluster().lag, f.cluster().fail = 1, true
		e.State.IP = "8.8.4.4"
		err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false)
		if err == nil || !strings.Contains(err.Error(), "Azure reports Failed") {
			t.Fatal(err)
		}
	})
}

func TestDocumentDBRefusesAPagedRuleList(t *testing.T) {
	e, f := allowlistFixture(t)
	f.cluster().paged = true
	e.State.IP = "8.8.4.4"
	err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false)
	if err == nil || !strings.Contains(err.Error(), "more than one page") {
		t.Fatal(err)
	}
	for key := range f.writes {
		if strings.HasPrefix(key, "docdb:") || strings.HasPrefix(key, "nsg:") {
			t.Fatal("wrote before proving the rule absent:", key)
		}
	}
}

func TestIPListsKeepUnrelatedEntriesAndFollowEveryIdentity(t *testing.T) {
	e, f := allowlistFixture(t)
	a := e.Config.Actions["allow"]
	driveDevice(t, e, "8.8.4.4")
	assertList(t, f, "storage:filesaccount", "9.9.9.9", "4.2.2.0/24", "8.8.4.4")
	assertList(t, f, "keyvault:secrets-vault", "9.9.9.9/32", "4.2.2.0/24", "8.8.4.4/32")
	home := deviceEngine(t, e.Config, f, "sam@desktop")
	driveDevice(t, home, "1.1.1.1")
	// An address inside a listed range is already allowed; the CLI would not add it.
	other := deviceEngine(t, e.Config, f, "lee@laptop")
	driveDevice(t, other, "4.2.2.2")
	driveDevice(t, e, "208.67.222.222")
	assertList(t, f, "storage:filesaccount", "9.9.9.9", "4.2.2.0/24", "1.1.1.1", "208.67.222.222")
	assertList(t, f, "keyvault:secrets-vault", "9.9.9.9/32", "4.2.2.0/24", "1.1.1.1/32", "208.67.222.222/32")
	for _, key := range []string{"storage:filesaccount", "keyvault:secrets-vault"} {
		if len(f.lists[key].other) == 0 || f.lists["keyvault:secrets-vault"].other["defaultAction"] != "Deny" {
			t.Fatal("other network settings changed")
		}
	}
	if s := other.State.Action("allow").Targets["files"]; s == nil || s.AppliedIP != "4.2.2.2" {
		t.Fatal("an address inside a listed range got no receipt")
	}
	writes := len(f.writes)
	driveDevice(t, e, "208.67.222.222")
	if len(f.writes) != writes {
		t.Fatal("an unchanged list was rewritten")
	}
	if err := e.retireDevice(context.Background(), "allow", a, "sam@desktop"); err != nil {
		t.Fatal(err)
	}
	assertList(t, f, "storage:filesaccount", "9.9.9.9", "4.2.2.0/24", "208.67.222.222")
	assertList(t, f, "keyvault:secrets-vault", "9.9.9.9/32", "4.2.2.0/24", "208.67.222.222/32")
}

func TestIPListAndDocumentDBDryRunWriteNothing(t *testing.T) {
	e, f := allowlistFixture(t)
	e.Apply = false
	e.State.IP = "8.8.4.4"
	if err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal("dry run wrote", f.writes)
	}
}

func TestIPListRefusesAChangeMadeDuringPlanning(t *testing.T) {
	e, f := allowlistFixture(t)
	reads := 0
	l := f.lists["storage:filesaccount"]
	e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		if args[0] == "storage" && args[2] == "show" {
			if reads++; reads == 2 {
				// Someone adds an address between the planning read and the write.
				l.entries = append(l.entries, "1.0.0.1")
			}
		}
		return f.Run(ctx, program, args, env)
	})
	e.State.IP = "8.8.4.4"
	err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false)
	if err == nil || !strings.Contains(err.Error(), "changed during planning") {
		t.Fatal(err)
	}
	if f.writes["storage:add:filesaccount"] != 0 {
		t.Fatal("wrote from a stale plan")
	}
}

func TestPlanIPList(t *testing.T) {
	for _, c := range []struct {
		before, active, known, remove, add []string
	}{
		{[]string{"1.1.1.1", "8.8.4.4/32", "9.9.9.0/24"}, []string{"8.8.4.4"}, []string{"1.1.1.1", "8.8.4.4"}, []string{"1.1.1.1"}, nil},
		{[]string{"9.9.9.0/24"}, []string{"9.9.9.9", "4.4.4.4", "4.4.4.4"}, nil, nil, []string{"4.4.4.4"}},
		{[]string{"1.0.0.1"}, nil, nil, nil, nil},
		{[]string{"1.0.0.1", "4.2.2.2"}, nil, []string{"1.0.0.1", "4.2.2.2"}, []string{"1.0.0.1", "4.2.2.2"}, nil},
	} {
		remove, add := planIPList(c.before, c.active, c.known)
		if !slices.Equal(remove, c.remove) || !slices.Equal(add, c.add) {
			t.Fatal(c, remove, add)
		}
	}
}

func TestDeviceOnlyTargetsValidate(t *testing.T) {
	e, _ := allowlistFixture(t)
	for _, c := range []struct {
		name, want string
		edit       func(*config.Config, *config.ActionConfig)
	}{
		{"no devices", "allow/cluster: documentdb targets need devices", func(_ *config.Config, a *config.ActionConfig) {
			a.Devices = nil
			a.Targets = a.Targets[3:4]
		}},
		{"rule", "allow/files: a storage target needs only subscription, resource_group, and resource", func(_ *config.Config, a *config.ActionConfig) { a.Targets[4].Rule = "mine" }},
		{"server on a list", "allow/secrets: a keyvault target needs only subscription, resource_group, and resource", func(_ *config.Config, a *config.ActionConfig) { a.Targets[5].Server = "x" }},
		{"cluster name in a URL", "allow/cluster: a documentdb target needs only subscription, resource_group, and server", func(_ *config.Config, a *config.ActionConfig) { a.Targets[3].Server = "one/../two" }},
		{"group in a URL", "allow/cluster: a documentdb target needs only subscription, resource_group, and server", func(_ *config.Config, a *config.ActionConfig) { a.Targets[3].ResourceGroup = "g?x=1" }},
		{"duplicate list", "allow: files2: only one target per storage resource is allowed in a device action", func(_ *config.Config, a *config.ActionConfig) {
			dup := a.Targets[4]
			dup.ID = "files2"
			dup.Resource = "FilesAccount"
			a.Targets = append(a.Targets, dup)
		}},
		{"long profile", "allow: cluster: DocumentDB rule names include the profile name; use a profile name of at most 17 characters", func(c *config.Config, a *config.ActionConfig) {
			c.Profile = "eighteen-chars-xyz"
			a.Devices.TagPrefix = "netshift." + c.Profile + ".device."
			a.Devices.LegacyTag = ""
			a.Devices.LegacyIdentity = ""
		}},
	} {
		raw, _ := json.Marshal(e.Config)
		var cfg config.Config
		json.Unmarshal(raw, &cfg)
		a := cfg.Actions["allow"]
		c.edit(&cfg, &a)
		cfg.Actions = map[string]config.ActionConfig{"allow": a}
		if err := cfg.Validate(); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	longest := e.Config
	longest.Profile = "seventeen-chars-x"
	a := longest.Actions["allow"]
	a.Devices = &config.DevicesConfig{TagPrefix: "netshift." + longest.Profile + ".device.", HistoryLimit: 10}
	longest.Actions = map[string]config.ActionConfig{"allow": a}
	if err := longest.Validate(); err != nil {
		t.Fatal(err)
	}
	long := deviceRuleTarget(longest, a.Targets[3], strings.Repeat("u", 40)+"@"+strings.Repeat("h", 60)).Rule
	if len(long) != 80 {
		t.Fatal("longest DocumentDB rule name is", len(long), "characters")
	}
	shared := e.Config
	other := shared.Actions["allow"]
	other.Devices = &config.DevicesConfig{TagPrefix: "netshift.test.other.", HistoryLimit: 10}
	shared.Actions = map[string]config.ActionConfig{"allow": shared.Actions["allow"], "again": other}
	if err := config.ValidateDeviceActions(shared); err == nil || !strings.Contains(err.Error(), "share a PostgreSQL server, DocumentDB cluster, storage account, or key vault") {
		t.Fatal(err)
	}
}

func TestIPListRefusesSurprisesAndLimits(t *testing.T) {
	for _, c := range []struct {
		name, want string
		edit       func(*deviceCloud)
	}{
		{"no network rules", "no network rules to keep", func(f *deviceCloud) { f.lists["keyvault:secrets-vault"].other = nil }},
		{"another resource", "identity does not match", func(f *deviceCloud) { f.lists["storage:filesaccount"].id += "-elsewhere" }},
		{"full list", "would exceed Azure's limit of 400 entries", func(f *deviceCloud) {
			l := f.lists["storage:filesaccount"]
			for i := range 397 {
				l.entries = append(l.entries, fmt.Sprintf("11.0.%d.%d", i/250, i%250+1))
			}
		}},
	} {
		e, f := allowlistFixture(t)
		c.edit(f)
		e.State.IP = "8.8.4.4"
		err := e.runDevices(context.Background(), "allow", e.Config.Actions["allow"], e.State.IP, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		for key := range f.writes {
			if strings.HasPrefix(key, "storage:") || strings.HasPrefix(key, "keyvault:") {
				t.Errorf("%s: wrote %s", c.name, key)
			}
		}
	}
}

func TestLateStaleListWriteIsCaught(t *testing.T) {
	e, f := allowlistFixture(t)
	driveDevice(t, e, "8.8.4.4")
	stale := false
	f.afterWrite = func(key string) {
		// A watcher with an old registry puts the previous address back just
		// after this pass verified the list.
		if key == "keyvault:add:secrets-vault" && !stale {
			stale = true
			l := f.lists["storage:filesaccount"]
			l.entries = append(l.entries, "8.8.4.4")
		}
	}
	driveDevice(t, e, "208.67.222.222")
	assertList(t, f, "storage:filesaccount", "9.9.9.9", "4.2.2.0/24", "208.67.222.222")
}

// TestLegacyProfileAddsAPostgresServerWithoutRule checks that a server added
// after a legacy migration gets its per-identity rule and nothing else.
func TestLegacyProfileAddsAPostgresServerWithoutRule(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	if a.Devices.LegacyIdentity != e.Config.Identity {
		t.Fatal("fixture is not a legacy profile")
	}
	added := fixtureTarget("added", "postgres")
	added.Rule, added.BootstrapIP = "", ""
	a.Targets = append(a.Targets, added)
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	f.pg["added"] = map[string]azureRule{}
	driveDevice(t, e, "8.8.4.4")
	own := deviceRuleTarget(e.Config, added, e.Config.Identity).Rule
	if r := f.pg["added"][own]; r.StartIP != "8.8.4.4" || len(f.pg["added"]) != 1 {
		t.Fatal(f.pg["added"])
	}
	if err := e.retireDevice(context.Background(), "allow", a, e.Config.Identity); err != nil {
		t.Fatal(err)
	}
	if len(f.pg["added"]) != 0 {
		t.Fatal("retirement left", f.pg["added"])
	}
}
