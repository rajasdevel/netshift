package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
)

type initRunner struct {
	target config.Target
	rule   azureRule
	calls  [][]string
}

func (r *initRunner) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{}, args...))
	if args[0] == "account" {
		return json.Marshal(subscriptionInfo{ID: r.target.Subscription, Name: "Example subscription"})
	}
	if args[0] == "network" && args[3] == "show" {
		return json.Marshal(r.rule)
	}
	if args[0] == "postgres" && args[2] == "show" {
		t := r.target
		t.Kind = "postgres"
		t.Server = "example-db"
		t.Rule = ""
		return json.Marshal(map[string]string{"name": t.Server, "id": strings.TrimSuffix(expectedResourceID(t), "/firewallRules/")})
	}
	panic("setup issued an unexpected command")
}
func initFixture() *initRunner {
	target := fixtureTarget("example-nsg", "nsg")
	target.ResourceGroup = "example-group"
	target.Rule = "developer-ssh"
	raw, _ := json.Marshal(fixtureRule(target, "8.8.8.8"))
	var rule azureRule
	_ = json.Unmarshal(raw, &rule)
	return &initRunner{target: target, rule: rule}
}
func TestInitCapturesOnlySelectedRulesWithoutCloudWrites(t *testing.T) {
	r := initFixture()
	c, err := prepareAzureProfile(context.Background(), r, "az", r.target.Subscription, "work", "sam@laptop", []string{"8.8.8.8"}, []string{"example-group/example-nsg/developer-ssh"}, []resourceSelection{{config.KindPostgres, "example-group/example-db"}})
	if err != nil {
		t.Fatal(err)
	}
	a := c.Actions["azure_allowlist"]
	if c.Identity != "" || a.Devices.SeedIdentity != "sam@laptop" || a.Devices.LegacyIdentity != "" || len(a.Targets) != 2 {
		t.Fatal("nonportable or unintended ownership", c)
	}
	if a.Targets[0].RuleShape != ruleShape(r.rule) || a.Targets[0].Template.Description != r.rule.Description {
		t.Fatal("template lost permissions or comments")
	}
	if a.Targets[1].Rule != "" || a.TimeoutSeconds != 900 {
		t.Fatal("new PG server incorrectly configured as legacy", a)
	}
	if len(r.calls) != 3 {
		t.Fatal(r.calls)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	raw, _ := config.JSON(c)
	if err = fsx.WriteNew(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = config.Load(path); err != nil {
		t.Fatal(err)
	}
	// Windows has no mode bits; %LOCALAPPDATA%'s access list protects files.
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("profile is not private")
	}
}
func TestInitRefusesUnownedOrChangedRule(t *testing.T) {
	for _, scenario := range []string{"unowned", "identity", "deny", "asg"} {
		t.Run(scenario, func(t *testing.T) {
			r := initFixture()
			switch scenario {
			case "unowned":
				r.rule.Source = "1.1.1.1/32"
			case "identity":
				r.rule.Name = "another-rule"
			case "deny":
				r.rule.Access = "Deny"
			case "asg":
				r.rule.SourceASGs = []json.RawMessage{json.RawMessage(`{"id":"example"}`)}
			}
			_, err := prepareAzureProfile(context.Background(), r, "az", r.target.Subscription, "work", "sam@laptop", []string{"8.8.8.8"}, []string{"example-group/example-nsg/developer-ssh"}, nil)
			if err == nil {
				t.Fatal("accepted unexpected source or rule")
			}
		})
	}
}
func TestSeedIPsBelongOnlyToTheSetupIdentity(t *testing.T) {
	e, f := deviceFixture(t)
	a := e.Config.Actions["allow"]
	a.Devices.SeedIdentity = e.Config.Identity
	a.Devices.LegacyIdentity = ""
	a.Devices.LegacyTag = ""
	a.Targets[2].Rule = ""
	e.Config.Actions["allow"] = a
	if err := e.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	driveDevice(t, e, "8.8.4.4")
	other := deviceEngine(t, e.Config, f, "lee@desktop")
	reg, err := other.loadDevices(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	own, err := other.ownDeviceHistory("allow", a, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 0 {
		t.Fatal("another identity inherited setup history", own)
	}
	if f.pg["database"]["managed-ip"].StartIP != "8.8.8.8" {
		t.Fatal("fresh setup deleted an unconfigured old PostgreSQL rule")
	}
	driveDevice(t, other, "1.1.1.1")
	assertDeviceIPs(t, e, f, "9.9.9.9", "8.8.4.4", "1.1.1.1")
}

func TestSeedOwnerDoesNotAdoptUnlabeledLegacyRegistry(t *testing.T) {
	e, _ := deviceFixture(t)
	a := e.Config.Actions["allow"]
	a.Devices.SeedIdentity = e.Config.Identity
	a.Devices.LegacyIdentity = "sam@desktop"
	own, err := e.ownDeviceHistory("allow", a, deviceRegistry{LegacyIPs: []string{"1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if containsIP(own, "1.1.1.1") {
		t.Fatal("setup identity adopted another identity's legacy registry history")
	}
	if !containsIP(own, "8.8.8.8") {
		t.Fatal("setup identity lost its confirmed seed IP")
	}
}

// An uppercase profile name is a usage error before any Azure CLI call.
func TestInitRejectsInvalidProfileNameBeforeAzure(t *testing.T) {
	r := &initRunner{}
	for _, name := range []string{"Work", "-work", "work.local", ""} {
		err := HandleInit(t.Context(), []string{"azure", "--subscription", "00000000-0000-0000-0000-000000000001",
			"--known-ip", "8.8.8.8", "--nsg-rule", "group/nsg/rule", "--profile", name, "--output", filepath.Join(t.TempDir(), "p.json")}, r, io.Discard)
		var bad *cmdline.UsageError
		if !errors.As(err, &bad) || !strings.Contains(bad.Message, "--profile") || len(r.calls) != 0 {
			t.Errorf("--profile %q: %v %q", name, err, r.calls)
		}
	}
}

// TestInitSelectsEveryResourceKind checks each new selection reads only its
// own resource and becomes a device-only target.
func TestInitSelectsEveryResourceKind(t *testing.T) {
	r := initFixture()
	reads := map[string]bool{}
	runner := runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		id, name := "", ""
		switch {
		case args[0] == "rest":
			if argValue(args, "--method") != "get" {
				t.Fatal("init wrote to Azure:", args)
			}
			id, _, _ = strings.Cut(argValue(args, "--url"), "?")
			name = id[strings.LastIndex(id, "/")+1:]
		case args[0] == "storage" && args[2] == "show":
			name = argValue(args, "--name")
			id = "/subscriptions/" + r.target.Subscription + "/resourceGroups/example-group/providers/Microsoft.Storage/storageAccounts/" + name
		case args[0] == "keyvault" && args[1] == "show":
			name = argValue(args, "--name")
			id = "/subscriptions/" + r.target.Subscription + "/resourceGroups/example-group/providers/Microsoft.KeyVault/vaults/" + name
		default:
			return r.Run(ctx, program, args, env)
		}
		reads[args[0]] = true
		return json.Marshal(map[string]string{"id": id, "name": name})
	})
	selections := []resourceSelection{{config.KindDocumentDB, "example-group/cluster-one"}, {config.KindStorage, "example-group/filesaccount"}, {config.KindKeyVault, "example-group/secrets-vault"}}
	c, err := prepareAzureProfile(context.Background(), runner, "az", r.target.Subscription, "work", "sam@laptop", []string{"8.8.8.8"}, []string{"example-group/example-nsg/developer-ssh"}, selections)
	if err != nil {
		t.Fatal(err)
	}
	targets := c.Actions["azure_allowlist"].Targets
	if len(targets) != 4 || targets[1].Server != "cluster-one" || targets[2].Resource != "filesaccount" || targets[3].Kind != config.KindKeyVault || len(reads) != 3 {
		t.Fatal(targets, reads)
	}
	selections[1].value = "example-group/elsewhere"
	runner2 := runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
		if args[0] == "storage" {
			return json.Marshal(map[string]string{"id": "/subscriptions/x/resourceGroups/other/providers/Microsoft.Storage/storageAccounts/elsewhere", "name": "elsewhere"})
		}
		return runner(ctx, program, args, env)
	})
	if _, err = prepareAzureProfile(context.Background(), runner2, "az", r.target.Subscription, "work", "sam@laptop", []string{"8.8.8.8"}, []string{"example-group/example-nsg/developer-ssh"}, selections); err == nil {
		t.Fatal("accepted a storage account from another place")
	}
}
