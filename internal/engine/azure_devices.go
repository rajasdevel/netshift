package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// Azure tag limits. Device records and markers each take one tag value.
const (
	maxTagValue = 256 // bytes in one tag value
	maxNSGTags  = 50  // tags on one resource
)

var (
	slugUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)
)

var (
	ipv4Token = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
)

// DeviceRecord is one identity's JSON tag value on every registry NSG. The
// keys are short because Azure limits a tag value to 256 bytes: "v" is the
// schema version (2), "id" the canonical user@host, "ips" its addresses
// newest first (current address at index 0, at most history_limit), "r" a
// revision that only grows, and "retired" marks a retirement marker, which
// lives under its own key (see deviceTag).
type DeviceRecord struct {
	Version  int      `json:"v"`
	Identity string   `json:"id"`
	IPs      []string `json:"ips"`
	Revision uint64   `json:"r"`
	Retired  bool     `json:"retired,omitempty"`
}

// captureTemplate records r's reviewed shape and description.
func captureTemplate(r azureRule) *config.NSGTemplate {
	return &config.NSGTemplate{Protocol: r.Protocol, Priority: r.Priority, Destinations: r.destinationList(), Ports: r.portList(), SourcePorts: r.sourcePortList(), Description: r.Description}
}

// legacyMarker replaces a migrated shared-history tag. Single-IP profiles
// reject it, so they cannot write the old format back. Field order is part of
// the stored encoding; keep it.
type legacyMarker struct {
	Mode    string `json:"mode"`
	Owner   string `json:"owner"`
	Prefix  string `json:"prefix"`
	Version int    `json:"v"`
}

// newLegacyMarker is the migration marker a's legacy owner writes.
func newLegacyMarker(a config.ActionConfig) legacyMarker {
	return legacyMarker{Mode: "devices", Owner: a.Devices.LegacyIdentity, Prefix: a.Devices.TagPrefix, Version: 2}
}

// isLegacyMarker reports whether raw is a's migration marker. The prefix is
// compared ignoring case: validateDevices lowercases tag_prefix, and a marker
// written under a mixed-case prefix is still this action's marker.
func isLegacyMarker(raw string, a config.ActionConfig) bool {
	var marker legacyMarker
	if json.Unmarshal([]byte(raw), &marker) != nil {
		return false
	}
	want := newLegacyMarker(a)
	return strings.EqualFold(marker.Prefix, want.Prefix) && marker.Mode == want.Mode && marker.Owner == want.Owner && marker.Version == want.Version
}

// BindIdentity ties state s to c's identity before any device action runs.
// It refuses state that belongs to another identity, and unlabeled legacy
// state unless c's identity is every device action's legacy_identity. It also
// refuses device actions that would share registry records or PostgreSQL
// rules (see config.ValidateDeviceActions).
func BindIdentity(c config.Config, s *store.State) error {
	if !config.HasDevices(c) {
		return nil
	}
	if err := config.ValidateDeviceActions(c); err != nil {
		return err
	}
	if c.Identity == "" {
		return errors.New("unresolved machine identity")
	}
	if s.Identity != "" && s.Identity != c.Identity {
		return fmt.Errorf("state belongs to %s, not %s; use a separate state file", s.Identity, c.Identity)
	}
	if s.Identity == "" && len(s.Actions) > 0 {
		for _, a := range c.Actions {
			if a.Devices != nil && a.Devices.LegacyIdentity != c.Identity {
				return errors.New("unlabeled legacy state cannot be adopted by another identity; use a new state file")
			}
		}
	}
	s.Identity = c.Identity
	return nil
}

// identitySlug is id's stable key fragment: a readable prefix and a hash.
func identitySlug(id string) string {
	slug := slugUnsafe.ReplaceAllString(strings.ToLower(id), "-")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return strings.Trim(slug, "-") + "-" + config.Fingerprint(id)[:12]
}

// deviceTag is the registry tag key of id's active record, or of its
// retirement marker when retired is set.
func deviceTag(a config.ActionConfig, id string, retired bool) string {
	suffix := ""
	if retired {
		suffix = "retired."
	}
	return a.Devices.TagPrefix + suffix + identitySlug(id)
}

// devicePGTarget is id's own PostgreSQL rule on t's server. The name includes
// the profile, so it is the same on every machine only because validateDevices
// requires the shared tag prefix to name the profile too.
func devicePGTarget(c config.Config, t config.Target, id string) config.Target {
	t.Rule = "netshift-" + c.Profile + "-" + identitySlug(id)
	t.BootstrapIP = ""
	t.KnownIPs = nil
	return t
}

// parseDevice decodes and validates one registry tag value: exactly one
// version-2 record of a canonical identity, with a revision and 1 to 10
// unique canonical public IPv4 addresses, within Azure's tag value limit.
func parseDevice(raw string) (DeviceRecord, error) {
	var d DeviceRecord
	if len(raw) > maxTagValue {
		return d, errors.New("device JSON exceeds Azure's 256-byte tag value limit")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return d, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return d, errors.New("device tag must contain exactly one JSON object")
	}
	id, err := config.CanonicalIdentity(d.Identity)
	if err != nil || id != d.Identity || d.Version != 2 || d.Revision == 0 || len(d.IPs) == 0 || len(d.IPs) > 10 {
		return d, errors.New("invalid device identity, schema, revision, or IP count")
	}
	if len(uniqueIPs(d.IPs)) != len(d.IPs) {
		return d, errors.New("device history must contain unique public IPv4 addresses")
	}
	for _, ip := range d.IPs {
		v, err := config.PublicIPv4(ip)
		if err != nil || v != ip {
			return d, errors.New("device history contains a noncanonical IP")
		}
	}
	return d, nil
}

// encodeDevice returns d's tag value: d with its addresses deduplicated, cut
// to limit, and then trimmed from the oldest until the JSON fits Azure's tag
// value limit, but never below five addresses.
//
// An active record is budgeted as the retirement marker that replaces it:
// the same addresses with ",\"retired\":true" and the next revision. So any
// active record can be re-encoded as a marker without losing an address, and
// retirement can always list every address of a record this version wrote.
func encodeDevice(d DeviceRecord, limit int) (string, error) {
	d.IPs = uniqueIPs(d.IPs)
	if len(d.IPs) > limit {
		d.IPs = d.IPs[:limit]
	}
	for {
		b, err := json.Marshal(d)
		if err != nil {
			return "", err
		}
		budget := b
		if !d.Retired {
			marker := d
			marker.Retired = true
			marker.Revision++
			if budget, err = json.Marshal(marker); err != nil {
				return "", err
			}
		}
		if len(budget) <= maxTagValue {
			if _, err = parseDevice(string(b)); err != nil {
				return "", err
			}
			return string(b), nil
		}
		if len(d.IPs) <= 5 {
			return "", errors.New("identity and minimum IP history exceed Azure tag limit; use a shorter identity")
		}
		d.IPs = d.IPs[:len(d.IPs)-1]
	}
}

// deviceRegistry is one read of every registry NSG of a device action.
//
// Devices holds each identity's effective record: its newest active record,
// or its retirement marker, which always wins. Histories holds every address
// that any record of the identity lists, active or retired, on any NSG: the
// addresses NetShift treats as that identity's. A retired identity therefore
// has no active address but keeps its history. NSGs holds the raw reads by
// lowercased resource ID, and LegacyIPs the unmigrated shared history that
// only legacy_identity may adopt.
//
// Skipped lists the records of other identities that could not be used;
// strict refuses them. Only retirement proceeds despite them, and then
// Protected holds every address they mention, which reconciliation neither
// adds to nor removes from a rule.
type deviceRegistry struct {
	Devices   map[string]DeviceRecord
	Histories map[string][]string
	NSGs      map[string]azureNSG
	LegacyIPs []string
	Skipped   []skippedRecord
	Protected []string
}

// skippedRecord is a registry tag that addNSG could not use. Identity is set
// when the record parsed but conflicts with another record of that identity.
type skippedRecord struct {
	NSG, Tag, Identity string
	Err                error
}

// errRegistryConflict marks two different records of one identity at one revision.
var errRegistryConflict = errors.New("conflicting device records")

// newRegistry returns an empty registry read.
func newRegistry() deviceRegistry {
	return deviceRegistry{Devices: map[string]DeviceRecord{}, Histories: map[string][]string{}, NSGs: map[string]azureNSG{}}
}

// merge adds one parsed record to the registry. Every address it lists joins
// its identity's history. The identity's effective record becomes d when d is
// a retirement marker and the current one is not, or when both are of one
// kind and d has the higher revision. Two different active records at one
// revision conflict. Two different markers at one revision, which two
// retirers can write concurrently, merge into one marker listing both
// address lists: markers only grow, so neither list may be dropped.
func (reg *deviceRegistry) merge(d DeviceRecord) error {
	old, found := reg.Devices[d.Identity]
	reg.Histories[d.Identity] = uniqueIPs(append(reg.Histories[d.Identity], d.IPs...))
	if found {
		if old.Retired && !d.Retired {
			return nil
		}
		if old.Retired == d.Retired {
			if old.Revision == d.Revision && config.Fingerprint(old) != config.Fingerprint(d) {
				if !d.Retired {
					return fmt.Errorf("%w for %s at revision %d; inspect duplicate identity installations", errRegistryConflict, d.Identity, d.Revision)
				}
				old.IPs = uniqueIPs(slices.Concat(old.IPs, d.IPs))
				reg.Devices[d.Identity] = old
				return nil
			}
			if old.Revision > d.Revision {
				return nil
			}
		}
	}
	reg.Devices[d.Identity] = d
	return nil
}

// addNSG adds one NSG's device records. An unusable record under one of
// owner's keys (its active record or retirement marker), or an unusable
// legacy tag, is an error. Any other unusable record is skipped: listed in
// Skipped and never merged.
func (reg *deviceRegistry) addNSG(n azureNSG, a config.ActionConfig, owner string) error {
	reg.NSGs[strings.ToLower(n.ID)] = n
	prefix := strings.ToLower(a.Devices.TagPrefix)
	spellings := map[string][]string{}
	for k := range n.Tags {
		if lower := strings.ToLower(k); strings.HasPrefix(lower, prefix) {
			spellings[lower] = append(spellings[lower], k)
		}
	}
	var own []string
	if owner != "" {
		own = []string{strings.ToLower(deviceTag(a, owner, false)), strings.ToLower(deviceTag(a, owner, true))}
	}
	for _, lower := range slices.Sorted(maps.Keys(spellings)) {
		keys := spellings[lower]
		d, err := reg.addDeviceTag(n, a, keys)
		if err == nil {
			continue
		}
		if slices.Contains(own, lower) || (errors.Is(err, errRegistryConflict) && d.Identity == owner) {
			return err
		}
		skipped := skippedRecord{NSG: n.Name, Tag: strings.Join(keys, ","), Err: err}
		if errors.Is(err, errRegistryConflict) {
			skipped.Identity = d.Identity
		}
		reg.Skipped = append(reg.Skipped, skipped)
		for _, k := range keys {
			reg.Protected = uniqueIPs(append(reg.Protected, ipv4Token.FindAllString(n.Tags[k], -1)...))
		}
	}
	return reg.addLegacyTag(n, a)
}

// addDeviceTag parses and merges the record stored under keys, the spellings
// of one device tag key on n. Its key must be the one its JSON owner and
// kind call for.
func (reg *deviceRegistry) addDeviceTag(n azureNSG, a config.ActionConfig, keys []string) (DeviceRecord, error) {
	if len(keys) > 1 {
		return DeviceRecord{}, fmt.Errorf("%s: duplicate device tag keys %q", n.Name, keys)
	}
	d, err := parseDevice(n.Tags[keys[0]])
	if err != nil {
		return d, fmt.Errorf("%s/%s: %w", n.Name, keys[0], err)
	}
	if !strings.EqualFold(keys[0], deviceTag(a, d.Identity, d.Retired)) {
		return DeviceRecord{}, fmt.Errorf("%s: device tag key does not match its JSON owner", keys[0])
	}
	return d, reg.merge(d)
}

// addLegacyTag adds n's unmigrated shared history, if any. A migration
// marker means the history was already migrated.
func (reg *deviceRegistry) addLegacyTag(n azureNSG, a config.ActionConfig) error {
	if a.Devices.LegacyTag == "" {
		return nil
	}
	_, raw, err := tagValue(n.Tags, a.Devices.LegacyTag)
	if err != nil || raw == "" {
		return err
	}
	if isLegacyMarker(raw, a) {
		return nil
	}
	_, _, h, err := historyTag(n.Tags, a.Devices.LegacyTag)
	if err != nil {
		return err
	}
	reg.LegacyIPs = uniqueIPs(append(reg.LegacyIPs, h.IPs...))
	return nil
}

// settle finishes a multi-NSG read: an identity with conflicting records is
// dropped from Devices, and every address it lists is protected.
func (reg *deviceRegistry) settle() {
	for _, s := range reg.Skipped {
		if s.Identity != "" {
			delete(reg.Devices, s.Identity)
			reg.Protected = uniqueIPs(append(reg.Protected, reg.Histories[s.Identity]...))
		}
	}
}

// strict refuses a registry that holds records it could not use.
func (reg deviceRegistry) strict() error {
	failures := make([]error, 0, len(reg.Skipped))
	for _, s := range reg.Skipped {
		failures = append(failures, s.Err)
	}
	return errors.Join(failures...)
}

// activeIPs is the sorted union of every active identity's current address.
func (reg deviceRegistry) activeIPs() []string {
	ips := []string{}
	for _, d := range reg.Devices {
		if !d.Retired {
			ips = append(ips, d.IPs[0])
		}
	}
	ips = uniqueIPs(ips)
	slices.Sort(ips)
	return ips
}

// knownIPs is every address the registry attributes to any identity,
// including retired identities and the legacy shared history.
func (reg deviceRegistry) knownIPs() []string {
	ips := append([]string{}, reg.LegacyIPs...)
	for _, h := range reg.Histories {
		ips = append(ips, h...)
	}
	return uniqueIPs(ips)
}

// removableIPs is knownIPs without the protected addresses: the addresses
// reconciliation may remove from a rule when no active identity uses them.
func (reg deviceRegistry) removableIPs() []string {
	return slices.DeleteFunc(reg.knownIPs(), func(ip string) bool { return slices.Contains(reg.Protected, ip) })
}

// deviceSources returns a registry rule's source list after reconciliation.
// The contract, for each entry of before in order:
//   - a single address in active stays where it is, in its original
//     notation; later entries for the same address are dropped;
//   - a single address in known but not in active is removed;
//   - every other entry (ranges, service tags, unrelated addresses, anything
//     that is not one public IPv4 address) stays byte-for-byte.
//
// Then each active address not yet present is appended as "IP/32", in active
// order. The union keeps a shared NAT address until its last active owner
// moves or retires. An empty result means no source remains.
func deviceSources(before, active, known []string) []string {
	owned := map[string]bool{}
	wanted := map[string]bool{}
	placed := map[string]bool{}
	for _, ip := range known {
		owned[ip] = true
	}
	for _, ip := range active {
		wanted[ip] = true
	}
	after := []string{}
	for _, source := range before {
		ip, err := singleIP(source)
		if err == nil && wanted[ip] {
			if !placed[ip] {
				after = append(after, source)
				placed[ip] = true
			}
			continue
		}
		if err == nil && owned[ip] {
			continue
		}
		after = append(after, source)
	}
	for _, ip := range active {
		if !placed[ip] {
			after = append(after, ip+"/32")
			placed[ip] = true
		}
	}
	return after
}

// validateDeviceNSG checks that r is t's registry rule, provisioned, with its
// reviewed inbound Allow shape and address sources only.
func validateDeviceNSG(r azureRule, t config.Target) error {
	if !strings.EqualFold(r.ID, expectedResourceID(t)) || r.Name != t.Rule {
		return errors.New("NSG rule identity mismatch")
	}
	if r.ProvisioningState != "" && r.ProvisioningState != "Succeeded" {
		return errors.New("NSG rule is still provisioning")
	}
	if !strings.EqualFold(r.Access, "Allow") || !strings.EqualFold(r.Direction, "Inbound") || len(r.SourceASGs) > 0 || len(r.DestinationASGs) > 0 || ruleShape(r) != t.RuleShape {
		return errors.New("NSG permissions, ports, destinations, or priority changed; review mapping")
	}
	return nil
}
