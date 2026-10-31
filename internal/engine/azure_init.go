package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
)

// InitOptions are the init command's options.
type InitOptions struct {
	subscription, profile, output, azureCLI string
	knownIPs, nsgRules, postgresServers     []string
}

// InitCommandLine describes init azure.
func InitCommandLine() (*cmdline.Line, *InitOptions) {
	f := cmdline.New("init", "init azure --subscription UUID --known-ip IP --nsg-rule GROUP/NSG/RULE [--postgres-server GROUP/SERVER] [--profile NAME] [--azure-cli PATH] --output FILE",
		"Generate a profile from selected existing Azure rules. Azure is only read; the new profile is never written over an existing file.")
	var o InitOptions
	appendTo := func(list *[]string) func(string) error {
		return func(v string) error { *list = append(*list, v); return nil }
	}
	f.StringVar(&o.subscription, "subscription", "", "explicit Azure subscription `UUID`")
	f.Func("known-ip", "a confirmed owned public `IP`; repeat for older IPs", appendTo(&o.knownIPs))
	f.Func("nsg-rule", "existing `GROUP/NSG/RULE` to manage; repeat for each rule", appendTo(&o.nsgRules))
	f.Func("postgres-server", "`GROUP/SERVER` for a new per-device PostgreSQL rule; repeat per server", appendTo(&o.postgresServers))
	f.StringVar(&o.profile, "profile", "work", "portable profile `NAME`")
	f.StringVar(&o.azureCLI, "azure-cli", "az", "Azure CLI `executable`: an absolute path or a command on PATH")
	f.StringVar(&o.output, "output", "", "new local profile `FILE` (existing files are never overwritten)")
	return f, &o
}

// HandleInit reads only the explicitly selected resources. It creates a local
// profile, never Azure rules, and assigns seed ownership solely to the
// installing identity.
func HandleInit(ctx context.Context, args []string, runner proc.Runner, out io.Writer) error {
	f, o := InitCommandLine()
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	if len(positional) != 1 || positional[0] != "azure" {
		return f.Errorf(`expected "azure"`)
	}
	if !config.SubscriptionID.MatchString(o.subscription) || o.output == "" || len(o.nsgRules) == 0 || len(o.knownIPs) == 0 {
		return f.Errorf("needs --subscription UUID, --output FILE, at least one --nsg-rule, and --known-ip")
	}
	// The profile check validate applies, so a bad name fails before any Azure read.
	if !config.ProfileName.MatchString(o.profile) {
		return f.Errorf("--profile must be 1 to 64 lowercase letters, digits, '-', or '_', starting with a letter or digit: %q", o.profile)
	}
	if strings.ContainsAny(o.azureCLI, "/\\") && !filepath.IsAbs(o.azureCLI) {
		return f.Errorf("--azure-cli must be an absolute path or a command on PATH")
	}
	for _, ip := range o.knownIPs {
		normal, err := config.PublicIPv4(ip)
		if err != nil || normal != ip {
			return f.Errorf("--known-ip must be a canonical public IPv4: %q", ip)
		}
	}
	path, err := filepath.Abs(o.output)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		return errors.New("output already exists; choose a new path and review before replacing a profile")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	identity, err := config.ResolveIdentity("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c, err := prepareAzureProfile(ctx, runner, o.azureCLI, o.subscription, o.profile, identity, o.knownIPs, o.nsgRules, o.postgresServers)
	if err != nil {
		return err
	}
	raw, err := config.JSON(c)
	if err != nil {
		return err
	}
	if err = fsx.WriteNew(path, raw); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		printCreated(out, path, len(c.Actions[config.ActionAzure].Targets), identity)
		return nil
	}
	fmt.Fprintf(out, "Created %s for %d selected rules/servers. Seed IPs belong to %s.\nReview the profile, then preview: netshift --config %s devices enroll\nAzure was only read; enrollment requires --apply.\n", path, len(c.Actions[config.ActionAzure].Targets), identity, cmdline.ShellQuote(path))
	return nil
}

// splitResource splits a GROUP/NSG/RULE or GROUP/SERVER selection into its
// count names, refusing empty names, names that look like options, and
// control characters.
func splitResource(value string, count int) ([]string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != count {
		return nil, fmt.Errorf("expected %d slash-separated resource names: %q", count, value)
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "\r\n\t") {
			return nil, fmt.Errorf("invalid resource selection %q", value)
		}
	}
	return parts, nil
}

// prepareAzureProfile builds a profile from the selected rules and servers.
// It only reads Azure: it confirms the subscription, captures each NSG rule's
// reviewed template and the known IPs it already holds, and confirms each
// PostgreSQL server. Seed ownership goes to identity alone.
func prepareAzureProfile(ctx context.Context, runner proc.Runner, az, sub, profile, identity string, known, nsgSelections, pgSelections []string) (config.Config, error) {
	c := config.Config{Version: 1, Profile: profile, KnownIPs: uniqueIPs(known), Actions: map[string]config.ActionConfig{}}
	a := config.ActionConfig{Type: config.ActionAzure, AzureCLI: az, Devices: &config.DevicesConfig{SeedIdentity: identity}, Targets: []config.Target{}}
	raw, err := runner.Run(ctx, az, []string{"account", "show", "--subscription", sub, "--query", "{name:name,id:id}", "--only-show-errors", "--output", "json"}, nil)
	if err != nil {
		return c, err
	}
	var account subscriptionInfo
	if err = json.Unmarshal(raw, &account); err != nil {
		return c, err
	}
	if !strings.EqualFold(account.ID, sub) {
		return c, errors.New("the Azure CLI returned a different subscription than requested")
	}
	for _, selection := range nsgSelections {
		parts, err := splitResource(selection, 3)
		if err != nil {
			return c, err
		}
		t := config.Target{Kind: config.KindNSG, Subscription: sub, ResourceGroup: parts[0], NSG: parts[1], Rule: parts[2], SourceMode: config.SourceReplaceKnown}
		t.ID = "nsg-" + config.Fingerprint(strings.ToLower(expectedResourceID(t)))[:16]
		raw, err := runner.Run(ctx, az, targetArgs(t, "show"), nil)
		if err != nil {
			return c, fmt.Errorf("%s: %w", selection, err)
		}
		var r azureRule
		if err = json.Unmarshal(raw, &r); err != nil {
			return c, err
		}
		t.RuleShape = ruleShape(r)
		t.Template = captureTemplate(r)
		if err = validateDeviceNSG(r, t); err != nil {
			return c, fmt.Errorf("%s: %w", selection, err)
		}
		for _, source := range r.sourceList() {
			if ip, err := singleIP(source); err == nil && containsIP(known, ip) {
				t.KnownIPs = append(t.KnownIPs, ip)
			}
		}
		t.KnownIPs = uniqueIPs(t.KnownIPs)
		if len(t.KnownIPs) == 0 {
			return c, fmt.Errorf("%s has no matching confirmed owned IP; inspect it and supply the correct --known-ip", selection)
		}
		a.Targets = append(a.Targets, t)
	}
	for _, selection := range pgSelections {
		parts, err := splitResource(selection, 2)
		if err != nil {
			return c, err
		}
		t := config.Target{Kind: config.KindPostgres, Subscription: sub, ResourceGroup: parts[0], Server: parts[1]}
		t.ID = "postgres-" + config.Fingerprint(strings.ToLower(expectedResourceID(t)))[:16]
		raw, err := runner.Run(ctx, az, []string{"postgres", "flexible-server", "show", "--subscription", sub, "--resource-group", t.ResourceGroup, "--name", t.Server, "--query", "{id:id,name:name}", "--only-show-errors", "--output", "json"}, nil)
		if err != nil {
			return c, err
		}
		var server struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err = json.Unmarshal(raw, &server); err != nil {
			return c, err
		}
		expected := strings.TrimSuffix(expectedResourceID(t), "/firewallRules/")
		if !strings.EqualFold(server.ID, expected) || server.Name != t.Server {
			return c, errors.New("PostgreSQL server identity mismatch")
		}
		a.Targets = append(a.Targets, t)
	}
	c.Actions[config.ActionAzure] = a
	return c, c.Validate()
}
