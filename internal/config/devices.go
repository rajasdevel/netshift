package config

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strings"
)

// Patterns compiled once: identity checks run for every registry tag read.
var (
	identityUser = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
)

var (
	identityHost = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
)

var (
	devicePrefix = regexp.MustCompile(`^netshift\.[a-zA-Z0-9_.-]{1,80}\.$`)
)

// DevicesConfig enables per-device ownership. Each identity owns one active
// tag. A separate retirement marker wins over stale active writes, including
// a process that was asleep during retirement.
type DevicesConfig struct {
	SeedIdentity     string `json:"seed_identity,omitempty"`
	TagPrefix        string `json:"tag_prefix"`
	HistoryLimit     int    `json:"history_limit"`
	ReconcileSeconds int    `json:"reconcile_seconds"`
	LegacyTag        string `json:"legacy_tag,omitempty"`
	LegacyIdentity   string `json:"legacy_identity,omitempty"`
}

// NSGTemplate is the reviewed shape of a registry NSG rule, captured from
// Azure. Only explicit enrollment uses it, to restore a rule that the last
// owner's retirement deleted.
type NSGTemplate struct {
	Protocol     string   `json:"protocol"`
	Priority     int      `json:"priority"`
	Destinations []string `json:"destinations"`
	Ports        []string `json:"ports"`
	SourcePorts  []string `json:"source_ports"`
	Description  string   `json:"description,omitempty"`
}

// NSGShape is the part of an NSG rule a reviewed template fixes: everything
// but the mutable source list and the description.
type NSGShape struct {
	Access, Direction, Protocol      string
	Priority                         int
	Destinations, Ports, SourcePorts []string
	SourceASGs, DestinationASGs      []json.RawMessage
}

// Fingerprint hashes the shape. Case and list order do not count, and an
// empty application security group list equals an absent one. Profiles
// store this value as rule_shape, so its encoding must not change.
func (s NSGShape) Fingerprint() string {
	sorted := func(v []string) []string { return slices.Sorted(slices.Values(v)) }
	if len(s.SourceASGs) == 0 {
		s.SourceASGs = nil
	}
	if len(s.DestinationASGs) == 0 {
		s.DestinationASGs = nil
	}
	return Fingerprint(struct {
		Access, Direction, Protocol      string
		Priority                         int
		Destinations, Ports, SourcePorts []string
		SourceASGs, DestinationASGs      []json.RawMessage
	}{
		strings.ToLower(s.Access), strings.ToLower(s.Direction), strings.ToLower(s.Protocol), s.Priority,
		sorted(s.Destinations), sorted(s.Ports), sorted(s.SourcePorts), s.SourceASGs, s.DestinationASGs,
	})
}

// Shape returns the shape of the inbound Allow rule t restores.
func (t NSGTemplate) Shape() NSGShape {
	return NSGShape{Access: "Allow", Direction: "Inbound", Protocol: t.Protocol, Priority: t.Priority, Destinations: t.Destinations, Ports: t.Ports, SourcePorts: t.SourcePorts}
}

// CanonicalIdentity returns value as a canonical user@host identity: the
// hostname lowercased and without a ".local" suffix.
func CanonicalIdentity(value string) (string, error) {
	name, host, ok := strings.Cut(value, "@")
	if !ok || strings.Contains(host, "@") || !identityUser.MatchString(name) {
		return "", errors.New("identity must be user@host with a short local username")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".local")
	if !identityHost.MatchString(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return "", errors.New("invalid identity hostname")
	}
	return name + "@" + host, nil
}

// ResolveIdentity returns value as a canonical identity, or this machine's
// user@host when value is empty.
func ResolveIdentity(value string) (string, error) {
	if value != "" {
		return CanonicalIdentity(value)
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return CanonicalIdentity(u.Username + "@" + host)
}

// HasDevices reports whether any action of c is a device action.
func HasDevices(c Config) bool {
	for _, a := range c.Actions {
		if a.Devices != nil {
			return true
		}
	}
	return false
}

// validateDevices fills a device action's defaults and checks it: the tag
// prefix (lowercased, as Azure tag keys ignore case), history and reconcile
// bounds, legacy and seed identities, and every target. NSG targets need a
// reviewed template that explicit enrollment can restore. Checks across
// actions are in ValidateDeviceActions.
func validateDevices(profile string, a *ActionConfig) error {
	d := a.Devices
	if a.SharedIPHistory != nil {
		return errors.New("devices and shared_ip_history are mutually exclusive")
	}
	if d.TagPrefix == "" {
		d.TagPrefix = "netshift." + profile + ".device."
	}
	// Azure compares tag keys ignoring case and the default prefix is
	// lowercase, so storing one spelling keeps keys and comparisons equal.
	d.TagPrefix = strings.ToLower(d.TagPrefix)
	d.HistoryLimit = cmp.Or(d.HistoryLimit, 10)
	d.ReconcileSeconds = cmp.Or(d.ReconcileSeconds, 1800)
	switch {
	case !devicePrefix.MatchString(d.TagPrefix):
		return fmt.Errorf("devices.tag_prefix must look like netshift.%s.NAME. (got %q)", profile, d.TagPrefix)
	case d.HistoryLimit < 5 || d.HistoryLimit > 10:
		return fmt.Errorf("devices.history_limit must be 5..10 (got %d)", d.HistoryLimit)
	case d.ReconcileSeconds < 60 || d.ReconcileSeconds > 86400:
		return fmt.Errorf("devices.reconcile_seconds must be 60..86400 (got %d)", d.ReconcileSeconds)
	}
	// Machines that share a registry derive each other's PostgreSQL rule names
	// (see devicePGTarget). Profile names cannot contain ".", so this prefix
	// fixes the profile, and any retirer computes the retired identity's name.
	if want := "netshift." + profile + "."; !strings.HasPrefix(d.TagPrefix, want) {
		return fmt.Errorf("devices tag_prefix must start with %q: PostgreSQL rule names include the profile name, so machines sharing a registry must share it", want)
	}
	// legacy_identity alone adopts old unlabeled history and PostgreSQL rule
	// names; legacy_tag additionally converts an old shared-history tag.
	if d.LegacyTag != "" && d.LegacyIdentity == "" {
		return errors.New("legacy_tag requires legacy_identity")
	}
	if d.LegacyIdentity != "" {
		id, err := CanonicalIdentity(d.LegacyIdentity)
		if err != nil || id != d.LegacyIdentity {
			return errors.New("legacy_identity must be canonical")
		}
	}
	if d.LegacyTag != "" && (!netshiftTag.MatchString(d.LegacyTag) || strings.HasPrefix(strings.ToLower(d.LegacyTag), d.TagPrefix)) {
		return errors.New("invalid legacy tag")
	}
	if d.SeedIdentity != "" {
		id, err := CanonicalIdentity(d.SeedIdentity)
		if err != nil || id != d.SeedIdentity {
			return errors.New("seed_identity must be canonical")
		}
	}
	seen := map[string]bool{}
	for _, t := range a.Targets {
		switch t.Kind {
		case KindNSG:
			if t.SourceMode != SourceReplaceKnown || t.Template == nil || t.Template.Shape().Fingerprint() != t.RuleShape {
				return fmt.Errorf("%s: devices needs a reviewed NSG template matching rule_shape", t.ID)
			}
			r := t.Template
			if r.Priority < 100 || r.Priority > 4096 || len(r.Ports) == 0 || len(r.Destinations) == 0 || len(r.SourcePorts) == 0 || r.Protocol == "" {
				return fmt.Errorf("%s: incomplete NSG template", t.ID)
			}
			// The Azure CLI reads an argument that starts with @ as a file
			// name, so such a description could never be restored.
			if strings.HasPrefix(r.Description, "@") {
				return fmt.Errorf("%s: an NSG template description cannot start with @, which the Azure CLI reads as a file name; change the rule's description in Azure, then capture the profile again", t.ID)
			}
		case KindPostgres:
			key := strings.ToLower(t.Subscription + "/" + t.ResourceGroup + "/" + t.Server)
			if seen[key] {
				return errors.New("only one PostgreSQL target per server is allowed in a device action")
			}
			seen[key] = true
			if t.Template != nil {
				return errors.New("PostgreSQL targets cannot have NSG templates")
			}
		}
	}
	if len(NSGGroups(*a)) == 0 {
		return errors.New("devices requires an NSG registry")
	}
	return nil
}

// ValidateDeviceActions refuses device actions of c that would share state.
// Registry records are keyed by tag prefix and identity on each NSG, so two
// actions whose prefixes overlap (one starts with the other) must not share
// a registry NSG: each would read the other's records, and retirement
// markers, as its own. PostgreSQL rule names depend only on the profile and
// the identity (see devicePGTarget), so two actions must not share a server.
func ValidateDeviceActions(c Config) error {
	type registry struct {
		name, prefix  string
		nsgs, servers map[string]bool
	}
	shares := func(x, y map[string]bool) bool {
		for k := range x {
			if y[k] {
				return true
			}
		}
		return false
	}
	var seen []registry
	for _, name := range ActionNames(c) {
		a := c.Actions[name]
		if a.Devices == nil {
			continue
		}
		r := registry{name: name, prefix: strings.ToLower(a.Devices.TagPrefix), nsgs: map[string]bool{}, servers: map[string]bool{}}
		for _, t := range a.Targets {
			switch t.Kind {
			case KindNSG:
				r.nsgs[strings.ToLower(NSGResourceID(t))] = true
			case KindPostgres:
				r.servers[strings.ToLower(t.Subscription+"/"+t.ResourceGroup+"/"+t.Server)] = true
			}
		}
		for _, o := range seen {
			if shares(o.servers, r.servers) {
				return fmt.Errorf("device actions %s and %s share a PostgreSQL server; their per-identity rules would have the same names", o.name, r.name)
			}
			if (strings.HasPrefix(o.prefix, r.prefix) || strings.HasPrefix(r.prefix, o.prefix)) && shares(o.nsgs, r.nsgs) {
				return fmt.Errorf("device actions %s and %s share a registry NSG with overlapping tag prefixes; give each action its own tag_prefix", o.name, r.name)
			}
		}
		seen = append(seen, r)
	}
	return nil
}
