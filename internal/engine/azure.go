package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// azureRule is the part of an Azure CLI rule document that NetShift reads.
// One type serves NSG security rules (access, direction, protocol, address
// prefixes, ports, application security groups) and PostgreSQL flexible-server
// firewall rules (StartIP and EndIP). Azure reports each address or port set
// either as a single value (Source, "sourceAddressPrefix") or as a list
// (Sources, "sourceAddressPrefixes") and leaves the other empty; the *List
// methods merge the two forms. Fields not listed here are compared as a whole
// by immutableRule.
type azureRule struct {
	Description       string            `json:"description,omitempty"`
	ProvisioningState string            `json:"provisioningState"`
	Name              string            `json:"name"`
	ID                string            `json:"id"`
	Access            string            `json:"access"`
	Direction         string            `json:"direction"`
	Protocol          string            `json:"protocol"`
	Priority          int               `json:"priority"`
	Source            string            `json:"sourceAddressPrefix"`
	Sources           []string          `json:"sourceAddressPrefixes"`
	SourcePort        string            `json:"sourcePortRange"`
	SourcePorts       []string          `json:"sourcePortRanges"`
	Destination       string            `json:"destinationAddressPrefix"`
	Destinations      []string          `json:"destinationAddressPrefixes"`
	Port              string            `json:"destinationPortRange"`
	Ports             []string          `json:"destinationPortRanges"`
	StartIP           string            `json:"startIpAddress"`
	EndIP             string            `json:"endIpAddress"`
	SourceASGs        []json.RawMessage `json:"sourceApplicationSecurityGroups"`
	DestinationASGs   []json.RawMessage `json:"destinationApplicationSecurityGroups"`
}

// sourceList, destinationList, portList, and sourcePortList return each
// address or port set in either Azure form (see singleOrList).
func (r azureRule) sourceList() []string      { return singleOrList(r.Source, r.Sources) }
func (r azureRule) destinationList() []string { return singleOrList(r.Destination, r.Destinations) }
func (r azureRule) portList() []string        { return singleOrList(r.Port, r.Ports) }
func (r azureRule) sourcePortList() []string  { return singleOrList(r.SourcePort, r.SourcePorts) }

// singleOrList returns Azure's list form when it is set, else the single
// value as a one-element list, else nil.
func singleOrList(single string, list []string) []string {
	if len(list) > 0 {
		return list
	}
	if single != "" {
		return []string{single}
	}
	return nil
}

// az runs the action's Azure CLI. The CLI replaces any argument (or the part
// after its first "=") that starts with "@" with the contents of that local
// file. Values here can come from Azure itself, such as a captured rule
// description, so refuse them rather than risk uploading a local file.
func (e *Engine) az(ctx context.Context, a config.ActionConfig, args []string) ([]byte, error) {
	for _, arg := range args {
		_, value, _ := strings.Cut(arg, "=")
		if strings.HasPrefix(arg, "@") || strings.HasPrefix(value, "@") {
			return nil, fmt.Errorf("refusing Azure CLI argument that starts with @: %q", arg)
		}
	}
	return e.Runner.Run(ctx, a.AzureCLI, args, nil)
}

// targetArgs returns the Azure CLI arguments that run verb on t's rule.
func targetArgs(t config.Target, verb string) []string {
	var args []string
	if t.Kind == config.KindNSG {
		args = []string{"network", "nsg", "rule", verb, "--nsg-name", t.NSG}
	} else {
		args = []string{"postgres", "flexible-server", "firewall-rule", verb, "--server-name", t.Server}
	}
	return append(args, "--subscription", t.Subscription, "--resource-group", t.ResourceGroup, "--name", t.Rule, "--only-show-errors", "--output", "json")
}

// expectedResourceID is the Azure resource ID of t's rule.
func expectedResourceID(t config.Target) string {
	parent := "Microsoft.Network/networkSecurityGroups/" + t.NSG + "/securityRules/"
	if t.Kind == config.KindPostgres {
		parent = "Microsoft.DBforPostgreSQL/flexibleServers/" + t.Server + "/firewallRules/"
	}
	return "/subscriptions/" + t.Subscription + "/resourceGroups/" + t.ResourceGroup + "/providers/" + parent + t.Rule
}

// sameStrings reports whether a and b hold the same values in any order.
func sameStrings(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// singleIP returns the public IPv4 address that source names alone: a bare
// address or one /32 prefix. Any other source is an error.
func singleIP(source string) (string, error) {
	if p, e := netip.ParsePrefix(source); e == nil {
		if !p.Addr().Is4() || p.Bits() != 32 {
			return "", errors.New("source must be one IPv4 /32")
		}
		return config.PublicIPv4(p.Addr().String())
	}
	return config.PublicIPv4(source)
}

// decodeRule parses one Azure CLI rule document.
func decodeRule(data []byte) (azureRule, error) {
	var r azureRule
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("invalid Azure JSON: %w", err)
	}
	return r, nil
}

// parseRule decodes a dedicated rule and returns it with its single owned IP.
func parseRule(data []byte, t config.Target) (azureRule, string, error) {
	r, err := decodeRule(data)
	if err != nil {
		return r, "", err
	}
	ip, err := validateRule(r, t)
	return r, ip, err
}

// validateRule checks that r is t's dedicated rule in its reviewed shape and
// returns the single public IPv4 address it allows.
func validateRule(r azureRule, t config.Target) (string, error) {
	if r.ProvisioningState != "" && r.ProvisioningState != "Succeeded" {
		return "", fmt.Errorf("rule is still provisioning: %s", r.ProvisioningState)
	}
	if !strings.EqualFold(r.ID, expectedResourceID(t)) || r.Name != t.Rule {
		return "", errors.New("Azure resource identity does not match configured rule")
	}
	if t.Kind == config.KindPostgres {
		if r.StartIP != r.EndIP {
			return "", errors.New("refusing a shared PostgreSQL IP range")
		}
		return config.PublicIPv4(r.StartIP)
	}
	if !strings.EqualFold(r.Access, "Allow") || !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Protocol, "Tcp") || r.Priority != t.Priority {
		return "", errors.New("NSG access, direction, protocol, or priority changed; refusing update")
	}
	if !sameStrings(r.destinationList(), []string{t.Destination}) || !sameStrings(r.portList(), t.Ports) || !sameStrings(r.sourcePortList(), []string{"*"}) || len(r.SourceASGs) > 0 || len(r.DestinationASGs) > 0 {
		return "", errors.New("NSG destination, ports, or application security groups changed; refusing update")
	}
	sources := r.sourceList()
	if len(sources) != 1 {
		return "", errors.New("refusing a shared NSG source list; configure a dedicated single-IP rule")
	}
	return singleIP(sources[0])
}

// guardOwnedIP refuses a dedicated rule whose current address is neither
// desired nor one that t owns.
func guardOwnedIP(current, desired string, t config.Target, s *store.TargetState, extraKnown ...string) error {
	for _, known := range append([]string{desired, t.BootstrapIP, s.AppliedIP, s.PendingIP}, extraKnown...) {
		if known != "" && current == known {
			return nil
		}
	}
	return fmt.Errorf("rule now contains unexpected IP %s; inspect it before changing ownership", current)
}

// immutableRule is a rule document without the fields a source update may
// change. Values are arbitrary JSON, so callers compare with reflect.DeepEqual.
func immutableRule(data []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for _, k := range []string{"sourceAddressPrefix", "sourceAddressPrefixes", "startIpAddress", "endIpAddress", "etag", "provisioningState", "systemData"} {
		delete(m, k)
	}
	return m
}

// runAzure runs the Azure action name for event: device actions through
// runDevices, and single-IP or shared-history actions target by target.
// force re-applies targets whose receipts already match.
func (e *Engine) runAzure(ctx context.Context, name string, a config.ActionConfig, event store.Event, force bool) error {
	if a.Devices != nil {
		err := e.runDevices(ctx, name, a, event.IP, false)
		if errors.Is(err, errIdentityRetired) {
			// Observing a retirement is the expected end of this identity's
			// work, not a failure to retry or report.
			return nil
		}
		return err
	}
	desired, err := config.PublicIPv4(event.IP)
	if err != nil {
		return err
	}
	state := e.State.Action(name)
	known, groups, err := e.prepareSharedHistory(ctx, name, a, desired)
	if err != nil {
		return err
	}
	var failures []error
	for _, t := range a.Targets {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		s := state.Target(t.ID)
		if !force && s.AppliedIP == desired && s.PendingIP == "" && s.Fingerprint == targetPolicyFingerprint(t, a) && s.HistoryInitialized {
			continue
		}
		err = e.azureTarget(ctx, name, a, t, s, desired, known...)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", t.ID, err))
			record := store.HistoryRecord{Status: statusFailed, Action: name, Target: t.ID, ResourceID: expectedResourceID(t), IP: desired, Error: err.Error()}
			if s.PendingChange != nil {
				record.OperationID = s.PendingChange.OperationID
			}
			if historyErr := e.record(record); historyErr != nil {
				return errors.Join(append(failures, fmt.Errorf("history: %w", historyErr))...)
			}
			e.Log.Log("target_failed", map[string]any{"action": name, "target": t.ID, "error": err.Error()})
		}
	}
	// Re-read the cache after the source writes. This repairs a concurrent
	// history-tag overwrite when possible; it is not a distributed lock.
	if e.Apply {
		for _, group := range groups {
			if ctx.Err() != nil {
				failures = append(failures, ctx.Err())
				break
			}
			if _, err := e.ensureSharedHistory(ctx, name, a, group, desired, known); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// targetPlan is one target's source change, planned from a fresh rule read.
type targetPlan struct {
	raw                    []byte   // the rule document the plan was made from
	before, after, removed []string // see sourcePlan
}

// azureTarget brings one single-IP or mapped target to desired: plan from a
// fresh read, then either write and verify the change or settle a rule that
// already matches, and finally save the receipt.
func (e *Engine) azureTarget(ctx context.Context, name string, a config.ActionConfig, t config.Target, s *store.TargetState, desired string, extraKnown ...string) error {
	raw, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	p := targetPlan{raw: raw}
	if p.before, p.after, p.removed, err = sourcePlan(raw, t, s, desired, extraKnown...); err != nil {
		return err
	}
	// sourcePlan returns non-empty lists on success, so nil and empty never
	// need to be told apart here.
	if slices.Equal(p.before, p.after) {
		if err = e.settleUnchangedTarget(name, t, s, desired, p.before); err != nil {
			return err
		}
		return e.targetReceipt(a, t, s, desired)
	}
	placed := []string{s.AppliedIP}
	if s.PendingChange != nil {
		placed = append(placed, s.PendingChange.AfterSources...)
	}
	unplaced, err := e.unplacedRemovals(name, expectedResourceID(t), p.before, p.after, placed)
	if err != nil {
		return err
	}
	if !e.Apply {
		fields := map[string]any{"target": t.ID, "remove": p.removed, "to": desired, "before_sources": p.before, "after_sources": p.after}
		if len(unplaced) > 0 {
			fields["unplaced_removals"] = unplaced
		}
		e.Log.Log("would_replace_ip", fields)
		return nil
	}
	rec, err := e.beginTargetWrite(ctx, name, a, t, s, desired, p)
	if err != nil {
		return err
	}
	if err = e.writeTargetSources(ctx, a, t, desired, p.after); err != nil {
		return err
	}
	if rec.AfterSources, err = e.verifyTargetSources(ctx, a, t, s, desired, p, extraKnown); err != nil {
		return err
	}
	rec.Status = statusVerified
	if err = e.record(rec); err != nil {
		return fmt.Errorf("IP updated but history verification could not be saved: %w", err)
	}
	e.Log.Log("ip_replaced", map[string]any{"target": t.ID, "removed_ips": p.removed, "to": desired})
	e.logUnplacedRemovals(name, t.ID, unplaced)
	return e.targetReceipt(a, t, s, desired)
}

// beginTargetWrite refuses a stale preimage for a mapped rule, then saves the
// write intent to state and history before any cloud change. A pending intent
// for the same plan keeps its operation ID; any other is recorded superseded.
func (e *Engine) beginTargetWrite(ctx context.Context, name string, a config.ActionConfig, t config.Target, s *store.TargetState, desired string, p targetPlan) (store.HistoryRecord, error) {
	rec := store.HistoryRecord{Status: statusIntent, Action: name, Target: t.ID, ResourceID: expectedResourceID(t), IP: desired, RemovedIPs: p.removed, BeforeSources: p.before, AfterSources: p.after}
	if t.SourceMode == config.SourceReplaceKnown {
		// Refuse a stale preimage. This is not a distributed cloud lock: external
		// editors must still coordinate changes to the same shared rule.
		fresh, err := e.az(ctx, a, targetArgs(t, "show"))
		if err != nil {
			return rec, err
		}
		var oldMap, newMap map[string]any
		_ = json.Unmarshal(p.raw, &oldMap)
		_ = json.Unmarshal(fresh, &newMap)
		if !reflect.DeepEqual(oldMap, newMap) {
			return rec, errors.New("rule changed during planning; retry with a fresh source list")
		}
	}
	// A pending change always has non-empty before_sources, like p.before, so
	// a JSON round trip of state cannot turn a match into nil-versus-empty.
	if s.PendingChange != nil && s.PendingChange.IP == desired && slices.Equal(s.PendingChange.BeforeSources, p.before) {
		rec.OperationID = s.PendingChange.OperationID
	} else {
		rec.OperationID = store.OperationID()
	}
	if s.PendingChange != nil && s.PendingChange.OperationID != rec.OperationID {
		previous := *s.PendingChange
		previous.Status = statusSuperseded
		if err := e.record(previous); err != nil {
			return rec, err
		}
	}
	rec.At = e.now()
	s.PendingIP = desired
	s.PendingChange = &rec
	if err := e.save(); err != nil {
		return rec, fmt.Errorf("cannot persist write intent: %w", err)
	}
	if err := e.record(rec); err != nil {
		return rec, fmt.Errorf("cannot append history before write: %w", err)
	}
	return rec, nil
}

// writeTargetSources sends t's planned change: the NSG source list after, or
// the PostgreSQL range of desired.
func (e *Engine) writeTargetSources(ctx context.Context, a config.ActionConfig, t config.Target, desired string, after []string) error {
	args := targetArgs(t, "update")
	if t.Kind == config.KindNSG {
		args = append(args, "--source-address-prefixes")
		args = append(args, after...)
	} else {
		args = append(args, "--start-ip-address", desired, "--end-ip-address", desired)
	}
	_, err := e.az(ctx, a, args)
	return err
}

// verifyTargetSources reads the rule back and returns its sources when they
// are exactly the planned list and nothing else in the rule changed.
func (e *Engine) verifyTargetSources(ctx context.Context, a config.ActionConfig, t config.Target, s *store.TargetState, desired string, p targetPlan, extraKnown []string) ([]string, error) {
	after, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return nil, fmt.Errorf("update sent, verification failed: %w", err)
	}
	actual, expected, _, err := sourcePlan(after, t, s, desired, extraKnown...)
	if err != nil {
		return nil, fmt.Errorf("post-update guard: %w", err)
	}
	if !slices.Equal(actual, expected) || !sameStrings(actual, p.after) {
		return nil, errors.New("Azure read-back did not match the expected source list")
	}
	if !reflect.DeepEqual(immutableRule(p.raw), immutableRule(after)) {
		return nil, errors.New("other rule fields changed during update; inspect the rule before retrying")
	}
	return actual, nil
}

// settleUnchangedTarget handles a rule that already allows desired. A pending
// write for desired succeeded before an interruption and is reconciled, but
// only if every unrelated entry of its durable plan is still present; a
// pending write for another address is superseded. A first visit records the
// rule as a baseline.
func (e *Engine) settleUnchangedTarget(name string, t config.Target, s *store.TargetState, desired string, current []string) error {
	if s.PendingChange != nil {
		rec := *s.PendingChange
		if rec.IP == desired {
			// New entries from another editor are preserved, never silently removed.
			remaining := map[string]int{}
			for _, source := range current {
				remaining[source]++
			}
			for _, source := range rec.AfterSources {
				if ip, parseErr := singleIP(source); parseErr == nil && ip == desired {
					continue
				}
				if remaining[source] == 0 {
					return errors.New("pending write lost an unrelated source; inspect the rule before reconciling")
				}
				remaining[source]--
			}
			rec.Status = statusReconciled
		} else {
			rec.Status = statusSuperseded
		}
		rec.AfterSources = current
		if err := e.record(rec); err != nil {
			return err
		}
	}
	if (s.PendingChange == nil && !s.HistoryInitialized) || (s.PendingChange != nil && s.PendingChange.IP != desired) {
		if err := e.record(store.HistoryRecord{Status: statusBaseline, Action: name, Target: t.ID, ResourceID: expectedResourceID(t), IP: desired, BeforeSources: current, AfterSources: current}); err != nil {
			return err
		}
	}
	if !e.Apply || e.Verbose {
		e.Log.Log("ip_already_allowed", map[string]any{"target": t.ID, "ip": desired})
	}
	return nil
}

// targetReceipt records that t was verified at desired under the current policy.
func (e *Engine) targetReceipt(a config.ActionConfig, t config.Target, s *store.TargetState, desired string) error {
	s.AppliedIP = desired
	s.PendingIP = ""
	s.PendingChange = nil
	s.HistoryInitialized = true
	s.Fingerprint = targetPolicyFingerprint(t, a)
	s.VerifiedAt = e.now()
	return e.save()
}

// unplacedRemovals returns the addresses that changing a rule from before to
// after removes although they were neither in the rule when this identity
// last verified it (its newest verified after_sources for that rule in the
// local history) nor among placed, the sources its own applied or pending
// writes put there. Ownership is decided by address, so these removals are
// reported for review; they are never prevented here.
func (e *Engine) unplacedRemovals(name, resourceID string, before, after, placed []string) ([]string, error) {
	removed := removedIPs(before, after)
	if len(removed) == 0 {
		return nil, nil
	}
	verified, err := e.lastVerifiedSources(name, resourceID)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, source := range slices.Concat(verified, placed) {
		if ip, err := singleIP(source); err == nil {
			known[ip] = true
		}
	}
	var unplaced []string
	for _, ip := range removed {
		if !known[ip] {
			unplaced = append(unplaced, ip)
		}
	}
	return unplaced, nil
}

// removedIPs returns, once each and in order, the single addresses of before
// that after no longer holds in any notation.
func removedIPs(before, after []string) []string {
	kept := map[string]bool{}
	for _, source := range after {
		if ip, err := singleIP(source); err == nil {
			kept[ip] = true
		}
	}
	var removed []string
	for _, source := range before {
		if ip, err := singleIP(source); err == nil && !kept[ip] {
			removed = append(removed, ip)
		}
	}
	return uniqueIPs(removed)
}

// logUnplacedRemovals logs the removal of addresses this identity did not
// place (see unplacedRemovals), if any.
func (e *Engine) logUnplacedRemovals(name, target string, ips []string) {
	if len(ips) == 0 {
		return
	}
	e.Log.Log("unplaced_address_removed", map[string]any{"action": name, "target": target, "ips": ips,
		"note": "not in the rule when this identity last verified it; removed because NetShift decides ownership by address"})
}

// runAction runs one action once. executeAction has already applied the
// action's timeout to ctx.
func (e *Engine) runAction(ctx context.Context, name string, a config.ActionConfig, event store.Event, force bool) error {
	if a.Type == config.ActionAzure {
		return e.runAzure(ctx, name, a, event, force)
	}
	if !e.Apply {
		e.Log.Log("would_run_command", map[string]any{"action": name, "trigger": event.Type})
		return nil
	}
	_, err := e.Runner.Run(ctx, a.Command[0], a.Command[1:], EventEnvironment(event))
	return err
}
