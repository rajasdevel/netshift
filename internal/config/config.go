// Package config defines the profile format: a monitor and the named actions
// it drives. Load parses a profile strictly, and Validate fills its defaults
// and rejects anything invalid or ambiguous before an action can run.
package config

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// Config is one profile: a monitor and the named actions it drives. Profiles
// are trusted executable policy; validate fills defaults and rejects anything
// ambiguous before an action can run.
//
// Its field order is the key order of generated profiles (init azure and
// map --write-config); Config itself is never fingerprinted. The types it
// contains must keep their JSON names and field order: action configuration,
// including targets and checks, is hashed into persisted fingerprints.
type Config struct {
	Version       int                     `json:"version"`
	Profile       string                  `json:"profile"`
	Identity      string                  `json:"identity,omitempty"`
	KnownIPs      []string                `json:"known_ips,omitempty"`
	Monitor       MonitorConfig           `json:"monitor"`
	Notifications *NotificationConfig     `json:"notifications,omitempty"`
	Actions       map[string]ActionConfig `json:"actions"`
}

// MonitorConfig controls polling, confirmation, and retry timing. Zero values
// select the defaults shown in config/example.json.
type MonitorConfig struct {
	InterfaceChanges     bool     `json:"interface_changes,omitempty"`    // emit interface_changed
	ResumeAfterSeconds   int      `json:"resume_after_seconds,omitempty"` // emit monitor_resumed after a gap this long; 0 disables
	IntervalSeconds      int      `json:"interval_seconds"`               // delay between polls
	TimeoutSeconds       int      `json:"timeout_seconds"`                // bound for each IP discovery request
	Confirmations        int      `json:"confirmations"`                  // consecutive polls that confirm a new IP
	OfflineConfirmations int      `json:"offline_confirmations"`          // consecutive failures that confirm an outage
	RetrySeconds         int      `json:"retry_seconds"`                  // first retry delay after an action fails
	MaxRetrySeconds      int      `json:"max_retry_seconds"`              // cap for the doubling retry delay
	IPSources            []string `json:"ip_sources"`                     // 2 to 4 HTTPS endpoints on distinct hosts
}

// SharedIPHistoryConfig keeps a bounded IP history in an Azure tag that every
// machine sharing the profile reads, so a peer's addresses stay recognized.
type SharedIPHistoryConfig struct {
	Tag   string `json:"tag"`   // netshift.* tag on the NSG that holds the history
	Limit int    `json:"limit"` // addresses kept, 5..10
}

// ActionConfig is one named action: what runs, and on which events.
type ActionConfig struct {
	Checks          []CheckConfig          `json:"checks,omitempty"`            // probes that verify the action worked
	Devices         *DevicesConfig         `json:"devices,omitempty"`           // per-identity device registry (Azure)
	SharedIPHistory *SharedIPHistoryConfig `json:"shared_ip_history,omitempty"` // shared address history (Azure)
	Type            string                 `json:"type"`                        // ActionCommand or ActionAzure
	On              []string               `json:"on"`                          // subscribed events
	Command         []string               `json:"command,omitempty"`           // literal argv of a command action
	AzureCLI        string                 `json:"azure_cli,omitempty"`         // az executable of an Azure action
	TimeoutSeconds  int                    `json:"timeout_seconds"`             // bound for one attempt, including checks
	Targets         []Target               `json:"targets,omitempty"`           // rules an Azure action owns
}

// Target is one Azure rule an action owns: a network security group rule
// (KindNSG) or a PostgreSQL flexible server firewall rule (KindPostgres).
//
// For NSG rules, SourceMode selects how sources change. "" is a dedicated
// rule that holds exactly one owned IPv4 /32, which is replaced; Destination,
// Ports, and Priority pin its shape. SourceReplaceKnown is an existing shared
// rule: only KnownIPs and addresses this target applied are replaced, every
// other source stays byte for byte, RuleShape pins its permissions, and
// Template lets explicit enrollment restore it after last-owner retirement.
// For a device action, a PostgreSQL target's Rule is the legacy shared rule;
// each identity gets its own deterministic rule.
type Target struct {
	Template      *NSGTemplate `json:"template,omitempty"`     // reviewed rule that enrollment may restore
	SourceMode    string       `json:"source_mode,omitempty"`  // "" for a dedicated rule, or SourceReplaceKnown
	KnownIPs      []string     `json:"known_ips,omitempty"`    // owned addresses a mapped rule may contain
	RuleShape     string       `json:"rule_shape,omitempty"`   // hex SHA-256 of a mapped rule's captured shape
	ID            string       `json:"id"`                     // unique within the action
	Kind          string       `json:"kind"`                   // KindNSG or KindPostgres
	Subscription  string       `json:"subscription"`           // explicit subscription UUID
	ResourceGroup string       `json:"resource_group"`         // resource group of the NSG or server
	NSG           string       `json:"nsg,omitempty"`          // NSG name (KindNSG)
	Server        string       `json:"server,omitempty"`       // server name (KindPostgres)
	Rule          string       `json:"rule,omitempty"`         // rule name; device PostgreSQL rules are named per identity
	BootstrapIP   string       `json:"bootstrap_ip,omitempty"` // owned address a dedicated rule may hold before its first update
	Destination   string       `json:"destination,omitempty"`  // dedicated NSG rule's destination /32
	Ports         []string     `json:"ports,omitempty"`        // dedicated NSG rule's destination ports
	Priority      int          `json:"priority,omitempty"`     // dedicated NSG rule's priority, 100..4096
}

// Configuration and state vocabulary. These strings are part of the profile,
// state, and hook formats; never change their values.
const (
	ActionCommand = "command"
	ActionAzure   = "azure_allowlist"

	EventIPChanged            = "ip_changed"
	EventConnectivityLost     = "connectivity_lost"
	EventConnectivityRestored = "connectivity_restored"
	EventInterfaceChanged     = "interface_changed"
	EventMonitorResumed       = "monitor_resumed"
	EventManual               = "manual"
	EventReconcile            = "reconcile"

	KindNSG      = "nsg"
	KindPostgres = "postgres"

	// SourceReplaceKnown marks a mapped NSG rule whose known addresses are
	// replaced in place while every other source is preserved.
	SourceReplaceKnown = "replace_known"

	ConnectivityOnline  = "online"
	ConnectivityOffline = "offline"
)

// maxConfigBytes bounds a profile file; real profiles are a few KiB.
const maxConfigBytes = 1 << 20

var (
	identifier     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	SubscriptionID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	netshiftTag    = regexp.MustCompile(`^netshift\.[a-zA-Z0-9_.-]{1,100}$`)
	// Profile names become file names and service labels. Lowercase keeps
	// them distinct on case-insensitive file systems such as APFS.
	ProfileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// reservedIPv4 lists blocks that are never a machine's public address.
var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
}

// PublicIPv4 returns the canonical form of a single public IPv4 address.
func PublicIPv4(s string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("not a public IPv4 address: %q", s)
	}
	for _, block := range reservedIPv4 {
		if block.Contains(ip) {
			return "", fmt.Errorf("not a public IPv4 address: %q", s)
		}
	}
	return ip.String(), nil
}

// canonicalPublicIPv4 accepts only an address already in canonical form, so
// later exact comparisons cannot miss an owned address.
func canonicalPublicIPv4(s string) error {
	ip, err := PublicIPv4(s)
	if err == nil && ip != s {
		err = fmt.Errorf("write IPv4 address %q as %q", s, ip)
	}
	return err
}

// Load reads and validates one profile file (see Parse).
func Load(path string) (Config, error) {
	data, err := fsx.ReadFileLimit(path, maxConfigBytes)
	if errors.Is(err, fsx.ErrTooLarge) {
		return Config{}, fmt.Errorf("profile: %w", err)
	}
	if err != nil {
		return Config{}, err
	}
	return Parse(data)
}

// Parse decodes and validates one profile. Duplicate or case-variant keys,
// unknown fields, and invalid UTF-8 are rejected, so the reviewed text is
// what runs.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := jsonv2.Unmarshal(data, &c, jsonv2.RejectUnknownMembers(true)); err != nil {
		return c, fmt.Errorf("profile: %w", err)
	}
	return c, c.Validate()
}

// Validate fills defaults in place and rejects an invalid or ambiguous
// profile. It is idempotent: a validated profile validates again unchanged.
// Actions are checked in name order, so the reported error is deterministic.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return errors.New("profile version must be 1")
	}
	if !ProfileName.MatchString(c.Profile) {
		return errors.New("profile name must be 1 to 64 lowercase letters, digits, '-', or '_', starting with a letter or digit")
	}
	for _, ip := range c.KnownIPs {
		if err := canonicalPublicIPv4(ip); err != nil {
			return fmt.Errorf("known_ips: %w", err)
		}
	}
	if c.Identity != "" {
		id, err := CanonicalIdentity(c.Identity)
		if err != nil || id != c.Identity {
			return errors.New("identity must be canonical user@host (lowercase host, no .local suffix)")
		}
	}
	if err := ValidateNotifications(c.Notifications); err != nil {
		return err
	}
	if err := validateMonitor(&c.Monitor); err != nil {
		return err
	}
	if len(c.Actions) == 0 {
		return errors.New("configure at least one named action")
	}
	// resources detects one Azure rule managed by two targets, across actions.
	resources := map[string]bool{}
	for _, name := range ActionNames(*c) {
		a := c.Actions[name]
		if err := validateAction(c.Profile, name, &a, resources); err != nil {
			return err
		}
		c.Actions[name] = a
	}
	// Device actions must not share registry records or PostgreSQL rule names.
	return ValidateDeviceActions(*c)
}

// validateMonitor fills monitor defaults and checks their bounds. The
// defaults and ranges are documented in the README's polling section.
func validateMonitor(m *MonitorConfig) error {
	if m.ResumeAfterSeconds != 0 && (m.ResumeAfterSeconds < 60 || m.ResumeAfterSeconds > 86400) {
		return fmt.Errorf("monitor.resume_after_seconds must be 0 or 60..86400 (got %d)", m.ResumeAfterSeconds)
	}
	m.IntervalSeconds = cmp.Or(m.IntervalSeconds, 30)
	m.TimeoutSeconds = cmp.Or(m.TimeoutSeconds, 5)
	m.Confirmations = cmp.Or(m.Confirmations, 2)
	m.OfflineConfirmations = cmp.Or(m.OfflineConfirmations, 2)
	m.RetrySeconds = cmp.Or(m.RetrySeconds, 30)
	m.MaxRetrySeconds = cmp.Or(m.MaxRetrySeconds, 900)
	if len(m.IPSources) == 0 {
		m.IPSources = []string{"https://api4.ipify.org", "https://checkip.amazonaws.com"}
	}
	for _, f := range []struct {
		name          string
		value, lo, hi int
	}{
		{"interval_seconds", m.IntervalSeconds, 5, 86400},
		{"timeout_seconds", m.TimeoutSeconds, 1, 60},
		{"confirmations", m.Confirmations, 1, 10},
		{"offline_confirmations", m.OfflineConfirmations, 1, 10},
		{"retry_seconds", m.RetrySeconds, 5, 86400},
	} {
		if f.value < f.lo || f.value > f.hi {
			return fmt.Errorf("monitor.%s must be %d..%d (got %d)", f.name, f.lo, f.hi, f.value)
		}
	}
	if m.MaxRetrySeconds < m.RetrySeconds || m.MaxRetrySeconds > 86400 {
		return fmt.Errorf("monitor.max_retry_seconds must be retry_seconds (%d)..86400 (got %d)", m.RetrySeconds, m.MaxRetrySeconds)
	}
	if len(m.IPSources) < 2 || len(m.IPSources) > 4 {
		return errors.New("configure 2 to 4 independent HTTPS IPv4 sources")
	}
	seenHosts := map[string]bool{}
	for _, source := range m.IPSources {
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || seenHosts[strings.ToLower(u.Hostname())] {
			return errors.New("IP sources must be distinct HTTPS hosts without embedded credentials")
		}
		seenHosts[strings.ToLower(u.Hostname())] = true
	}
	return nil
}

// validateAction fills one action's defaults and checks it. resources holds
// the Azure rules claimed by the actions checked before it.
func validateAction(profile, name string, a *ActionConfig, resources map[string]bool) error {
	if !identifier.MatchString(name) {
		return fmt.Errorf("invalid action name %q", name)
	}
	if len(a.On) == 0 {
		a.On = []string{EventIPChanged, EventConnectivityRestored}
	}
	events := map[string]bool{}
	for _, e := range a.On {
		if !ValidEvent(e) || events[e] {
			return fmt.Errorf("%s: invalid or duplicate event %q", name, e)
		}
		events[e] = true
	}
	if err := ValidateChecks(a.Checks); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if a.TimeoutSeconds == 0 {
		a.TimeoutSeconds = 300
		if a.Devices != nil {
			a.TimeoutSeconds = 900
		}
	}
	if a.TimeoutSeconds < 1 || a.TimeoutSeconds > 1800 {
		return fmt.Errorf("%s: timeout_seconds must be 1..1800 (got %d)", name, a.TimeoutSeconds)
	}
	switch a.Type {
	case ActionAzure:
		return validateAzureAction(profile, name, a, events, resources)
	case ActionCommand:
		return validateCommandAction(name, a)
	default:
		return fmt.Errorf("%s: unknown action type %q", name, a.Type)
	}
}

// validateCommandAction checks a hook: a literal argv whose executable is an
// absolute path or a name looked up in PATH, with no Azure settings.
func validateCommandAction(name string, a *ActionConfig) error {
	if len(a.Command) > 0 && strings.ContainsAny(a.Command[0], `/\`) && !filepath.IsAbs(a.Command[0]) {
		return fmt.Errorf("%s: command executable must be an absolute path or a PATH command", name)
	}
	if len(a.Command) == 0 || strings.TrimSpace(a.Command[0]) == "" || len(a.Targets) != 0 || a.AzureCLI != "" || a.SharedIPHistory != nil || a.Devices != nil {
		return fmt.Errorf("%s: command actions need an argv array only", name)
	}
	return nil
}

// validateAzureAction checks an Azure allowlist action and its targets. Azure
// actions subscribe only to events that carry a confirmed online address.
func validateAzureAction(profile, name string, a *ActionConfig, events, resources map[string]bool) error {
	if a.AzureCLI == "" {
		a.AzureCLI = "az"
	}
	if strings.ContainsAny(a.AzureCLI, `/\`) && !filepath.IsAbs(a.AzureCLI) {
		return fmt.Errorf("%s: azure_cli must be an absolute path or a PATH command", name)
	}
	if len(a.Command) != 0 || len(a.Targets) == 0 || events[EventConnectivityLost] || events[EventInterfaceChanged] || events[EventMonitorResumed] {
		return fmt.Errorf("%s: Azure actions need targets and an online event", name)
	}
	if a.SharedIPHistory != nil {
		if err := validateSharedHistory(profile, name, a); err != nil {
			return err
		}
	}
	if a.Devices != nil {
		if err := validateDevices(profile, a); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	ids := map[string]bool{}
	for _, t := range a.Targets {
		if !identifier.MatchString(t.ID) || ids[t.ID] {
			return fmt.Errorf("%s: invalid or duplicate target ID %q", name, t.ID)
		}
		ids[t.ID] = true
		if err := validateAzureTarget(name, a, t); err != nil {
			return err
		}
		key := strings.ToLower(strings.Join([]string{t.Kind, t.Subscription, t.ResourceGroup, t.NSG, t.Server, t.Rule}, "/"))
		if resources[key] {
			return fmt.Errorf("duplicate managed Azure rule: %s", t.ID)
		}
		resources[key] = true
	}
	return nil
}

// validateSharedHistory fills shared_ip_history defaults and checks that an
// NSG target exists to hold the history tag.
func validateSharedHistory(profile, name string, a *ActionConfig) error {
	h := a.SharedIPHistory
	if h.Tag == "" {
		h.Tag = "netshift." + profile + ".ip-history"
	}
	if h.Limit == 0 {
		h.Limit = 10
	}
	if !netshiftTag.MatchString(h.Tag) || h.Limit < 5 || h.Limit > 10 {
		return fmt.Errorf("%s: shared_ip_history needs a netshift.* tag and a limit of 5..10", name)
	}
	if !slices.ContainsFunc(a.Targets, func(t Target) bool { return t.Kind == KindNSG }) {
		return fmt.Errorf("%s: shared_ip_history needs an NSG target to hold the registry", name)
	}
	return nil
}

// validateAzureTarget checks one target of the Azure action name. The caller
// checks that target IDs and managed rules are unique.
func validateAzureTarget(name string, a *ActionConfig, t Target) error {
	// Device-mode PostgreSQL rules are named per identity, so a profile
	// names a rule only for a legacy single-owner rule.
	ruleOptional := t.Kind == KindPostgres && a.Devices != nil && a.Devices.LegacyIdentity == ""
	if !SubscriptionID.MatchString(t.Subscription) || strings.TrimSpace(t.ResourceGroup) == "" ||
		(strings.TrimSpace(t.Rule) == "" && !ruleOptional) ||
		strings.HasPrefix(t.ResourceGroup, "-") || strings.HasPrefix(t.Rule, "-") {
		return fmt.Errorf("%s/%s: explicit subscription UUID, resource group, and rule required", name, t.ID)
	}
	// A dedicated rule without devices is adopted from bootstrap_ip, so it is
	// required there; wherever it is given it must be canonical.
	bootstrapRequired := t.SourceMode != SourceReplaceKnown && a.Devices == nil
	if t.BootstrapIP != "" || bootstrapRequired {
		if err := canonicalPublicIPv4(t.BootstrapIP); err != nil {
			return fmt.Errorf("%s/%s bootstrap_ip: %w", name, t.ID, err)
		}
	}
	switch t.Kind {
	case KindNSG:
		if t.SourceMode == SourceReplaceKnown {
			return validateMappedNSGTarget(t, a.Devices != nil)
		}
		return validateDedicatedNSGTarget(t)
	case KindPostgres:
		if t.SourceMode != "" || len(t.KnownIPs) != 0 || t.RuleShape != "" || t.Server == "" || strings.HasPrefix(t.Server, "-") ||
			t.NSG != "" || t.Destination != "" || len(t.Ports) != 0 || t.Priority != 0 {
			return fmt.Errorf("%s: invalid PostgreSQL target", t.ID)
		}
		return nil
	default:
		return fmt.Errorf("%s: unsupported Azure target kind %q", t.ID, t.Kind)
	}
}

// validateMappedNSGTarget checks an existing rule adopted by map: only its
// known addresses change, and its captured shape must still match.
func validateMappedNSGTarget(t Target, devices bool) error {
	if t.NSG == "" || strings.HasPrefix(t.NSG, "-") || t.Server != "" || (len(t.KnownIPs) == 0 && !devices) || len(t.RuleShape) != 64 {
		return fmt.Errorf("%s: mapped NSG target needs nsg, known_ips, and rule_shape", t.ID)
	}
	if _, err := hex.DecodeString(t.RuleShape); err != nil {
		return fmt.Errorf("%s: invalid rule_shape", t.ID)
	}
	for _, ip := range t.KnownIPs {
		if err := canonicalPublicIPv4(ip); err != nil {
			return fmt.Errorf("%s known_ips: %w", t.ID, err)
		}
	}
	if t.Destination != "" || len(t.Ports) != 0 || t.Priority != 0 || t.BootstrapIP != "" {
		return fmt.Errorf("%s: mapped targets use the captured rule_shape instead of dedicated-rule fields", t.ID)
	}
	return nil
}

// validateDedicatedNSGTarget checks a single-source rule that NetShift owns:
// one destination host, canonical unique ports, and a valid priority.
func validateDedicatedNSGTarget(t Target) error {
	if t.SourceMode != "" || len(t.KnownIPs) != 0 || t.RuleShape != "" {
		return fmt.Errorf("%s: unknown NSG source mode", t.ID)
	}
	if t.NSG == "" || strings.HasPrefix(t.NSG, "-") || t.Server != "" || t.Priority < 100 || t.Priority > 4096 || len(t.Ports) == 0 {
		return fmt.Errorf("%s: invalid NSG target", t.ID)
	}
	p, err := netip.ParsePrefix(t.Destination)
	if err != nil || !p.Addr().Is4() || p.Bits() != 32 {
		return fmt.Errorf("%s: destination must be the intended host's IPv4 /32", t.ID)
	}
	ports := map[int]bool{}
	for _, port := range t.Ports {
		n, err := strconv.Atoi(port)
		if err != nil || strconv.Itoa(n) != port || n < 1 || n > 65535 || ports[n] {
			return fmt.Errorf("%s: invalid or duplicate destination port %q", t.ID, port)
		}
		ports[n] = true
	}
	return nil
}

// Fingerprint is a stable hash of v's JSON encoding. It detects changes to
// configuration and state; the inputs are plain data that always marshal.
func Fingerprint(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ActionNames returns the action names in the stable order actions run.
func ActionNames(c Config) []string {
	return slices.Sorted(maps.Keys(c.Actions))
}

// Listens reports whether action a subscribes to event.
func Listens(a ActionConfig, event string) bool {
	return slices.Contains(a.On, event)
}

// ValidEvent reports whether a profile may subscribe to event s. The reconcile
// and manual events are internal triggers, not subscriptions.
func ValidEvent(s string) bool {
	switch s {
	case EventIPChanged, EventConnectivityLost, EventConnectivityRestored, EventInterfaceChanged, EventMonitorResumed:
		return true
	}
	return false
}
