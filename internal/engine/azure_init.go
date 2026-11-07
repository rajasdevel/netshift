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
	"slices"
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
	knownIPs, nsgRules                      []string
	resources                               []resourceSelection
}

// resourceSelection is one GROUP/NAME selection of a database server or
// cluster, or of a storage account or key vault, and its target kind.
type resourceSelection struct{ kind, value string }

// InitCommandLine describes init azure.
func InitCommandLine() (*cmdline.Line, *InitOptions) {
	f := cmdline.New("init", "init azure --subscription UUID --known-ip IP --nsg-rule GROUP/NSG/RULE [--postgres-server GROUP/SERVER] [--documentdb-cluster GROUP/CLUSTER] [--storage-account GROUP/ACCOUNT] [--key-vault GROUP/VAULT] [--profile NAME] [--azure-cli PATH] --output FILE",
		"Generate a profile from selected existing Azure rules. Azure is only read; the new profile is never written over an existing file.")
	var o InitOptions
	appendTo := func(list *[]string) func(string) error {
		return func(v string) error { *list = append(*list, v); return nil }
	}
	f.StringVar(&o.subscription, "subscription", "", "explicit Azure subscription `UUID`")
	f.Func("known-ip", "a confirmed owned public `IP`; repeat for older IPs", appendTo(&o.knownIPs))
	f.Func("nsg-rule", "existing `GROUP/NSG/RULE` to manage; repeat for each rule", appendTo(&o.nsgRules))
	selectKind := func(kind string) func(string) error {
		return func(v string) error { o.resources = append(o.resources, resourceSelection{kind, v}); return nil }
	}
	f.Func("postgres-server", "`GROUP/SERVER` for a new per-device PostgreSQL rule; repeat per server", selectKind(config.KindPostgres))
	f.Func("documentdb-cluster", "`GROUP/CLUSTER` for a new per-device DocumentDB rule; repeat per cluster", selectKind(config.KindDocumentDB))
	f.Func("storage-account", "`GROUP/ACCOUNT` whose IP list follows the devices; repeat per account", selectKind(config.KindStorage))
	f.Func("key-vault", "`GROUP/VAULT` whose IP list follows the devices; repeat per vault", selectKind(config.KindKeyVault))
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
	if len(o.profile) > config.MaxDocumentDBProfile && slices.ContainsFunc(o.resources, func(r resourceSelection) bool { return r.kind == config.KindDocumentDB }) {
		return f.Errorf("--documentdb-cluster needs a --profile of at most %d characters: DocumentDB rule names include it", config.MaxDocumentDBProfile)
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
	c, err := prepareAzureProfile(ctx, runner, o.azureCLI, o.subscription, o.profile, identity, o.knownIPs, o.nsgRules, o.resources)
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
	fmt.Fprintf(out, "Created %s for %d selected rules and resources. Seed IPs belong to %s.\nReview the profile, then preview: netshift --config %s devices enroll\nAzure was only read; enrollment requires --apply.\n", path, len(c.Actions[config.ActionAzure].Targets), identity, cmdline.ShellQuote(path))
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
		// The Azure CLI reads an argument, or the part after its first "=",
		// that starts with @ as a file name; Azure names have neither.
		if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "@=\r\n\t") {
			return nil, fmt.Errorf("invalid resource selection %q", value)
		}
	}
	return parts, nil
}

// prepareAzureProfile builds a profile from the selected rules and resources.
// It only reads Azure: it confirms the subscription, captures each NSG rule's
// reviewed template and the known IPs it already holds, and confirms that
// each other selected resource exists. Seed ownership goes to identity alone.
func prepareAzureProfile(ctx context.Context, runner proc.Runner, az, sub, profile, identity string, known, nsgSelections []string, resources []resourceSelection) (config.Config, error) {
	c := config.Config{Version: 1, Profile: profile, KnownIPs: uniqueIPs(known), Actions: map[string]config.ActionConfig{}}
	a := config.ActionConfig{Type: config.ActionAzure, AzureCLI: az, Devices: &config.DevicesConfig{SeedIdentity: identity}, Targets: []config.Target{}}
	raw, err := runAz(ctx, runner, az, []string{"account", "show", "--subscription", sub, "--query", "{name:name,id:id}", "--only-show-errors", "--output", "json"})
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
		raw, err := runAz(ctx, runner, az, targetArgs(t, "show"))
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
	for _, selection := range resources {
		parts, err := splitResource(selection.value, 2)
		if err != nil {
			return c, err
		}
		t := config.Target{Kind: selection.kind, Subscription: sub, ResourceGroup: parts[0]}
		if t.IPList() {
			t.Resource = parts[1]
		} else {
			t.Server = parts[1]
		}
		expected := strings.TrimSuffix(expectedResourceID(t), "/firewallRules/")
		t.ID = t.Kind + "-" + config.Fingerprint(strings.ToLower(expectedResourceID(t)))[:16]
		args := []string{"rest", "--method", "get", "--url", expected + documentDBAPI}
		switch t.Kind {
		case config.KindPostgres:
			args = []string{"postgres", "flexible-server", "show", "--name", t.Server}
		case config.KindStorage:
			args = []string{"storage", "account", "show", "--name", t.Resource}
		case config.KindKeyVault:
			args = []string{"keyvault", "show", "--name", t.Resource}
		}
		if t.Kind != config.KindDocumentDB {
			args = append(args, "--subscription", sub, "--resource-group", t.ResourceGroup)
		}
		raw, err := runAz(ctx, runner, az, append(args, "--query", "{id:id,name:name}", "--only-show-errors", "--output", "json"))
		if err != nil {
			return c, err
		}
		var found struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err = json.Unmarshal(raw, &found); err != nil {
			return c, err
		}
		if !strings.EqualFold(found.ID, expected) || found.Name != parts[1] {
			return c, fmt.Errorf("%s %s: resource identity mismatch", t.Kind, parts[1])
		}
		a.Targets = append(a.Targets, t)
	}
	c.Actions[config.ActionAzure] = a
	return c, c.Validate()
}
