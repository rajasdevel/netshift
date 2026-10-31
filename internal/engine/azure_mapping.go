package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

type subscriptionInfo struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}
type azureNSG struct {
	Tags          map[string]string `json:"tags"`
	Name          string            `json:"name"`
	ID            string            `json:"id"`
	ResourceGroup string            `json:"resourceGroup"`
	Location      string            `json:"location"`
	Rules         []azureRule       `json:"securityRules"`
	Defaults      []azureRule       `json:"defaultSecurityRules"`
	NICs          []struct {
		ID string `json:"id"`
	} `json:"networkInterfaces"`
	Subnets []struct {
		ID string `json:"id"`
	} `json:"subnets"`
}
type mappedRule struct {
	Name         string         `json:"name"`
	ID           string         `json:"id"`
	Access       string         `json:"access"`
	Direction    string         `json:"direction"`
	Protocol     string         `json:"protocol"`
	Priority     int            `json:"priority"`
	Sources      []string       `json:"sources"`
	Destinations []string       `json:"destinations"`
	Ports        []string       `json:"ports"`
	KnownIPs     []string       `json:"known_ip_matches,omitempty"`
	Disposition  string         `json:"disposition"`
	Target       *config.Target `json:"target,omitempty"`
}
type mappedNSG struct {
	Tags          map[string]string `json:"tags,omitempty"`
	Name          string            `json:"name"`
	ID            string            `json:"id"`
	ResourceGroup string            `json:"resource_group"`
	Location      string            `json:"location"`
	NICs          []string          `json:"network_interfaces"`
	Subnets       []string          `json:"subnets"`
	Rules         []mappedRule      `json:"custom_rules"`
	Defaults      []mappedRule      `json:"default_rules"`
}
type azureMapping struct {
	Version             int              `json:"version"`
	At                  time.Time        `json:"observed_at"`
	Subscription        subscriptionInfo `json:"subscription"`
	KnownIPs            []string         `json:"known_ips"`
	NSGs                []mappedNSG      `json:"nsgs"`
	CustomRules         int              `json:"custom_rule_count"`
	DefaultRules        int              `json:"default_rule_count"`
	MatchedRules        int              `json:"matched_rule_count"`
	MatchedNSGs         int              `json:"matched_nsg_count"`
	MissingManagedRules []string         `json:"missing_managed_rules,omitempty"`
}

// knownIPs is the profile's ownership evidence for mapping, sorted: the
// configured and bootstrap addresses, every target receipt, and history,
// the addresses that recentHistoryIPs extracted with ownershipIPs.
func knownIPs(c config.Config, s *store.State, history []string) []string {
	set := map[string]bool{}
	add := func(ip string) {
		if p, e := config.PublicIPv4(ip); e == nil {
			set[p] = true
		}
	}
	for _, ip := range c.KnownIPs {
		add(ip)
	}
	for name, a := range c.Actions {
		for _, t := range a.Targets {
			add(t.BootstrapIP)
			for _, ip := range t.KnownIPs {
				add(ip)
			}
			if as := s.Actions[name]; as != nil {
				if ts := as.Targets[t.ID]; ts != nil {
					add(ts.AppliedIP)
					add(ts.PendingIP)
				}
			}
		}
	}
	for _, ip := range history {
		add(ip)
	}
	return slices.Sorted(maps.Keys(set))
}

// buildMapping inventories nsgs of subscription sub. Each inbound Allow
// custom rule is classified: managed when c already targets it, a proposed
// mapped target when an exact known address is among its sources and it has
// no application security groups, and otherwise left alone. Configured rules
// that the inventory lacks are listed as missing.
func buildMapping(sub subscriptionInfo, nsgs []azureNSG, c config.Config, known []string) azureMapping {
	m := azureMapping{Version: 1, At: time.Now().UTC(), Subscription: sub, KnownIPs: known, NSGs: []mappedNSG{}}
	registry := map[string]bool{}
	for _, ip := range known {
		registry[ip] = true
	}
	existing := map[string]config.Target{}
	seen := map[string]bool{}
	for _, a := range c.Actions {
		for _, t := range a.Targets {
			if t.Kind == config.KindNSG && strings.EqualFold(t.Subscription, sub.ID) {
				existing[strings.ToLower(expectedResourceID(t))] = t
			}
		}
	}
	nsgs = slices.SortedFunc(slices.Values(nsgs), func(x, y azureNSG) int { return strings.Compare(x.ID, y.ID) })
	for _, n := range nsgs {
		group := mappedNSG{Tags: n.Tags, Name: n.Name, ID: n.ID, ResourceGroup: n.ResourceGroup, Location: n.Location, NICs: []string{}, Subnets: []string{}, Rules: []mappedRule{}, Defaults: []mappedRule{}}
		for _, v := range n.NICs {
			group.NICs = append(group.NICs, v.ID)
		}
		for _, v := range n.Subnets {
			group.Subnets = append(group.Subnets, v.ID)
		}
		count := 0
		convert := func(r azureRule, defaults bool) mappedRule {
			item := mappedRule{Name: r.Name, ID: r.ID, Access: r.Access, Direction: r.Direction, Protocol: r.Protocol, Priority: r.Priority, Sources: r.sourceList(), Destinations: r.destinationList(), Ports: r.portList(), Disposition: "no_known_ip_match"}
			found := map[string]bool{}
			for _, source := range item.Sources {
				if ip, e := singleIP(source); e == nil && registry[ip] && !found[ip] {
					item.KnownIPs = append(item.KnownIPs, ip)
					found[ip] = true
				}
			}
			seen[strings.ToLower(r.ID)] = true
			if defaults || !strings.EqualFold(r.Access, "Allow") || !strings.EqualFold(r.Direction, "Inbound") {
				item.Disposition = "excluded"
				return item
			}
			if target, ok := existing[strings.ToLower(r.ID)]; ok {
				item.Disposition = "managed"
				item.Target = &target
			} else if len(item.KnownIPs) > 0 && len(r.SourceASGs) == 0 && len(r.DestinationASGs) == 0 {
				id := "mapped-" + config.Fingerprint(strings.ToLower(r.ID))[:16]
				target := config.Target{ID: id, Kind: config.KindNSG, Subscription: sub.ID, ResourceGroup: n.ResourceGroup, NSG: n.Name, Rule: r.Name, SourceMode: config.SourceReplaceKnown, KnownIPs: item.KnownIPs, RuleShape: ruleShape(r), Template: captureTemplate(r)}
				item.Disposition = "known_ip_match"
				item.Target = &target
			}
			if item.Target != nil {
				count++
				m.MatchedRules++
			}
			return item
		}
		for _, r := range n.Rules {
			group.Rules = append(group.Rules, convert(r, false))
			m.CustomRules++
		}
		for _, r := range n.Defaults {
			group.Defaults = append(group.Defaults, convert(r, true))
			m.DefaultRules++
		}
		if count > 0 {
			m.MatchedNSGs++
		}
		m.NSGs = append(m.NSGs, group)
	}
	for id := range existing {
		if !seen[id] {
			m.MissingManagedRules = append(m.MissingManagedRules, id)
		}
	}
	slices.Sort(m.MissingManagedRules)
	return m
}

// mappingMarkdown renders m as a readable Markdown summary.
func mappingMarkdown(m azureMapping) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# NSG mapping: %s\n\nObserved: %s. Read-only inventory.\n\n%d NSGs, %d custom rules, %d default rules. %d existing rules across %d NSGs match configured ownership.\n\nKnown IPs: `%s`. Only exact IPv4 or /32 entries qualify; address ranges and name similarities do not establish ownership.\n\n", m.Subscription.Name, m.At.Format(time.RFC3339), len(m.NSGs), m.CustomRules, m.DefaultRules, m.MatchedRules, m.MatchedNSGs, strings.Join(m.KnownIPs, "`, `"))
	b.WriteString("| Resource group | NSG | Custom rules | Matched rules |\n| --- | --- | ---: | ---: |\n")
	for _, n := range m.NSGs {
		count := 0
		for _, r := range n.Rules {
			if r.Target != nil {
				count++
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d |\n", n.ResourceGroup, n.Name, len(n.Rules), count)
	}
	b.WriteString("\n## Existing rules eligible for replacement\n\n| NSG | Rule | Known source IPs | Other source entries preserved | Destination ports | Status |\n| --- | --- | --- | ---: | --- | --- |\n")
	for _, n := range m.NSGs {
		for _, r := range n.Rules {
			if r.Target == nil {
				continue
			}
			preserved := 0
			for _, source := range r.Sources {
				if ip, e := singleIP(source); e != nil || !slices.Contains(m.KnownIPs, ip) {
					preserved++
				}
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s |\n", n.Name, r.Name, strings.Join(r.KnownIPs, ", "), preserved, strings.Join(r.Ports, ", "), r.Disposition)
		}
	}
	if len(m.MissingManagedRules) > 0 {
		fmt.Fprintf(&b, "\nMissing configured rules: %s\n", strings.Join(m.MissingManagedRules, ", "))
	}
	b.WriteString("\nThe JSON companion contains every custom/default rule, source list, and NIC/subnet association. Mapping does not create, delete, or update cloud rules. Importing the proposed targets is an explicit configuration change.\n")
	return b.String()
}

// mergeMapping returns c with m's proposed targets added to the Azure action
// named action, skipping rules some action already targets, and m's known
// addresses as the profile's. It refuses a mapping with missing configured
// rules, and returns the validated result.
func mergeMapping(c config.Config, m azureMapping, action string) (config.Config, error) {
	a, ok := c.Actions[action]
	if !ok || a.Type != config.ActionAzure {
		return c, errors.New("choose an existing azure_allowlist action")
	}
	if len(m.MissingManagedRules) > 0 {
		return c, errors.New("configured NSG rules are missing; inspect mapping before importing")
	}
	seen := map[string]bool{}
	for _, other := range c.Actions {
		for _, t := range other.Targets {
			seen[strings.ToLower(expectedResourceID(t))] = true
		}
	}
	a.Targets = append([]config.Target{}, a.Targets...)
	for _, n := range m.NSGs {
		for _, r := range n.Rules {
			if r.Target == nil {
				continue
			}
			key := strings.ToLower(expectedResourceID(*r.Target))
			if !seen[key] {
				a.Targets = append(a.Targets, *r.Target)
				seen[key] = true
			}
		}
	}
	actions := map[string]config.ActionConfig{}
	maps.Copy(actions, c.Actions)
	actions[action] = a
	c.Actions = actions
	c.KnownIPs = append([]string{}, m.KnownIPs...)
	return c, c.Validate()
}

// MapOptions are the map command's flags.
type MapOptions struct {
	subscription, action, output, markdown, configOut string
	perMachine                                        bool
}

// MapCommandLine defines the map command's options, for parsing and for help.
func MapCommandLine(o *MapOptions) *cmdline.Line {
	f := cmdline.New("map", "--config FILE map [options]", "Inventory NSGs and map exact known IPs (read-only).")
	f.StringVar(&o.subscription, "subscription", "", "explicit subscription `UUID` (defaults to the action's single subscription)")
	f.StringVar(&o.action, "action", "", "the Azure action `NAME` to inspect or import")
	f.StringVar(&o.output, "output", "", "write the full JSON mapping to `FILE`")
	f.StringVar(&o.markdown, "markdown", "", "also write a readable mapping to `FILE`")
	f.StringVar(&o.configOut, "write-config", "", "write a proposed profile with mapped existing rules to `FILE`")
	f.BoolVar(&o.perMachine, "per-machine", false, "prepare a per-machine migration profile with reviewed NSG templates")
	return f
}

// parseMapOptions parses the map command's options; it takes no positional
// arguments.
func parseMapOptions(args []string) (MapOptions, error) {
	var o MapOptions
	f := MapCommandLine(&o)
	if err := f.ParseNone(args); err != nil {
		return o, err
	}
	if o.perMachine && o.configOut == "" {
		return o, f.Errorf("--per-machine requires --write-config")
	}
	return o, nil
}

// resolveMapTarget fills in the only Azure action and its only subscription
// when the options leave them out.
func resolveMapTarget(c config.Config, o *MapOptions) (config.ActionConfig, error) {
	if o.action == "" {
		for _, name := range config.ActionNames(c) {
			if c.Actions[name].Type == config.ActionAzure {
				if o.action != "" {
					return config.ActionConfig{}, errors.New("multiple Azure actions: specify --action")
				}
				o.action = name
			}
		}
	}
	a, ok := c.Actions[o.action]
	if !ok || a.Type != config.ActionAzure {
		return a, errors.New("map needs an azure_allowlist action")
	}
	if o.subscription == "" {
		set := map[string]bool{}
		for _, t := range a.Targets {
			set[t.Subscription] = true
		}
		if len(set) != 1 {
			return a, errors.New("multiple subscriptions: specify --subscription")
		}
		for id := range set {
			o.subscription = id
		}
	}
	if !config.SubscriptionID.MatchString(o.subscription) {
		return a, errors.New("subscription must be an explicit UUID")
	}
	return a, nil
}

// readInventory reads the subscription's identity and every NSG in it.
func readInventory(ctx context.Context, runner proc.Runner, a config.ActionConfig, subID string) (subscriptionInfo, []azureNSG, error) {
	var sub subscriptionInfo
	account, err := runner.Run(ctx, a.AzureCLI, []string{"account", "show", "--subscription", subID, "--query", "{name:name,id:id}", "--only-show-errors", "-o", "json"}, nil)
	if err != nil {
		return sub, nil, err
	}
	if err = json.Unmarshal(account, &sub); err != nil {
		return sub, nil, err
	}
	if !strings.EqualFold(sub.ID, subID) {
		return sub, nil, errors.New("subscription identity mismatch")
	}
	data, err := runner.Run(ctx, a.AzureCLI, []string{"network", "nsg", "list", "--subscription", subID, "--only-show-errors", "-o", "json"}, nil)
	if err != nil {
		return sub, nil, err
	}
	var nsgs []azureNSG
	if err = json.Unmarshal(data, &nsgs); err != nil {
		return sub, nil, err
	}
	return sub, nsgs, nil
}

// mapKnownIPs is the ownership evidence used to match rules. A device action
// uses only this identity's own history; a shared-history action adds the
// cached history of the NSGs it manages, never of another team's NSGs that
// happen to use the same profile name elsewhere in the subscription.
func mapKnownIPs(c config.Config, state *store.State, statePath, name string, a config.ActionConfig, nsgs []azureNSG, known []string) ([]string, error) {
	managed := map[string]bool{}
	for _, t := range config.NSGGroups(a) {
		managed[strings.ToLower(config.NSGResourceID(t))] = true
	}
	if a.Devices != nil {
		if err := BindIdentity(c, state); err != nil {
			return nil, err
		}
		reg := newRegistry()
		for _, n := range nsgs {
			if !managed[strings.ToLower(n.ID)] {
				continue
			}
			if err := reg.addNSG(n, a, c.Identity); err != nil {
				return nil, err
			}
		}
		reg.settle()
		if err := reg.strict(); err != nil {
			return nil, err
		}
		engine := Engine{Config: c, State: state, StatePath: statePath}
		return engine.ownDeviceHistory(name, a, reg)
	}
	if a.SharedIPHistory != nil {
		for _, n := range nsgs {
			if !managed[strings.ToLower(n.ID)] {
				continue
			}
			_, _, cached, err := historyTag(n.Tags, a.SharedIPHistory.Tag)
			if err != nil {
				return nil, fmt.Errorf("%s shared history: %w", n.Name, err)
			}
			known = uniqueIPs(append(known, cached.IPs...))
		}
	}
	return known, nil
}

// HandleMap writes a read-only inventory of the subscription's NSGs and,
// with --write-config, a proposed profile that adopts matching rules.
func HandleMap(ctx context.Context, c config.Config, statePath string, args []string, runner proc.Runner, out io.Writer) error {
	o, err := parseMapOptions(args)
	if err != nil {
		return err
	}
	a, err := resolveMapTarget(c, &o)
	if err != nil {
		return err
	}
	state, err := store.Load(statePath)
	if err != nil {
		return err
	}
	history, err := recentHistoryIPs(store.HistoryPath(statePath), ownershipWindow, ownershipIPs)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	sub, nsgs, err := readInventory(ctx, runner, a, o.subscription)
	if err != nil {
		return err
	}
	known, err := mapKnownIPs(c, state, statePath, o.action, a, nsgs, knownIPs(c, state, history))
	if err != nil {
		return err
	}
	m := buildMapping(sub, nsgs, c, known)
	if err = writeMapping(c, o, m, nsgs, out); err != nil {
		return err
	}
	if o.output != "" {
		fmt.Fprintf(out, "Mapped %d NSGs / %d custom rules; %d existing rules across %d NSGs match known IPs.\n", len(m.NSGs), m.CustomRules, m.MatchedRules, m.MatchedNSGs)
	}
	return nil
}

// writeMapping writes the JSON mapping (to stdout without --output), the
// optional Markdown summary, and the optional proposed profile.
func writeMapping(c config.Config, o MapOptions, m azureMapping, nsgs []azureNSG, out io.Writer) error {
	payload, _ := json.MarshalIndent(m, "", "  ")
	if o.output != "" {
		if err := fsx.AtomicWrite(o.output, append(payload, '\n'), 0600); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(out, string(payload))
	}
	if o.markdown != "" {
		if err := fsx.AtomicWrite(o.markdown, []byte(mappingMarkdown(m)), 0600); err != nil {
			return err
		}
	}
	if o.configOut == "" {
		return nil
	}
	next, err := mergeMapping(c, m, o.action)
	if err != nil {
		return err
	}
	if o.perMachine {
		if next, err = prepareDeviceConfig(next, o.action, nsgs); err != nil {
			return err
		}
	}
	if config.HasDevices(next) {
		next.Identity = "" // exported profiles detect the installing user and host
	}
	b, err := config.JSON(next)
	if err != nil {
		return err
	}
	return fsx.AtomicWrite(o.configOut, b, 0600)
}

// prepareDeviceConfig converts action name to a device action. It only reads
// Azure: it freezes the exact existing NSG permissions and comments so
// explicit enrollment can restore a last-owner-retired rule.
func prepareDeviceConfig(c config.Config, name string, nsgs []azureNSG) (config.Config, error) {
	a := c.Actions[name]
	if a.Devices != nil {
		return c, nil
	}
	id, err := config.ResolveIdentity(c.Identity)
	if err != nil {
		return c, err
	}
	d := &config.DevicesConfig{TagPrefix: "netshift." + c.Profile + ".device.", HistoryLimit: 10, ReconcileSeconds: 1800, LegacyIdentity: id, LegacyTag: legacyHistoryTag(c, a, nsgs)}
	if a.SharedIPHistory != nil {
		d.HistoryLimit = a.SharedIPHistory.Limit
	}
	a.Targets = append([]config.Target{}, a.Targets...)
	for i, t := range a.Targets {
		if t.Kind != config.KindNSG {
			continue
		}
		var rule azureRule
		found := false
		for _, n := range nsgs {
			if strings.EqualFold(n.ID, config.NSGResourceID(t)) {
				rule, found = findNSGRule(n, t)
				break
			}
		}
		if !found {
			return c, fmt.Errorf("missing migration target %s", t.ID)
		}
		if t.SourceMode == config.SourceReplaceKnown {
			if t.RuleShape != ruleShape(rule) {
				return c, fmt.Errorf("%s permissions changed; review mapping before migration", t.ID)
			}
		} else if _, err = validateRule(rule, t); err != nil {
			return c, err
		}
		t.KnownIPs = uniqueIPs(append(t.KnownIPs, t.BootstrapIP))
		t.SourceMode = config.SourceReplaceKnown
		t.RuleShape = ruleShape(rule)
		t.Template = captureTemplate(rule)
		t.BootstrapIP = ""
		t.Destination = ""
		t.Ports = nil
		t.Priority = 0
		a.Targets[i] = t
	}
	a.SharedIPHistory = nil
	// PostgreSQL firewall create/delete pollers can each take a full minute.
	// First enrollment also migrates legacy names; leave a bounded 15 minutes.
	if a.TimeoutSeconds < 900 {
		a.TimeoutSeconds = 900
	}
	a.Devices = d
	c.Actions[name] = a
	return c, c.Validate()
}

// legacyHistoryTag is the shared-history tag that migration turns into a
// marker, or "" when no shared history ever existed: none is configured and
// no managed NSG carries the default tag. A marker then would only spend one
// of the NSG's 50 tag slots.
func legacyHistoryTag(c config.Config, a config.ActionConfig, nsgs []azureNSG) string {
	if a.SharedIPHistory != nil {
		return a.SharedIPHistory.Tag
	}
	tag := "netshift." + c.Profile + ".ip-history"
	for _, t := range config.NSGGroups(a) {
		for _, n := range nsgs {
			if strings.EqualFold(n.ID, config.NSGResourceID(t)) {
				// Case-variant duplicates are ambiguous: keep the tag so that
				// enrollment refuses them for inspection.
				if _, _, found, err := lookupTag(n.Tags, tag); found || err != nil {
					return tag
				}
			}
		}
	}
	return ""
}
