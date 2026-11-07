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

// Storage accounts and key vaults allow a plain list of addresses, with no
// name on an entry, so NetShift decides ownership by address, as it does for
// a device NSG rule's sources (see deviceSources): every active identity's
// current address stays or is added; a single address that a registry
// record lists and no active identity uses is removed; everything else, and
// every other network setting, is left alone.

// ipListLimit is the most IP entries Azure allows on t's resource.
func ipListLimit(t config.Target) int {
	if t.Kind == config.KindStorage {
		return 400
	}
	return 1000
}

// ipList is one read of a storage account or key vault: the document, for
// comparing everything but the IP entries, and the entries as Azure spells
// them.
type ipList struct {
	raw     []byte
	entries []string
}

// ipListArgs returns the Azure CLI arguments that run verb on t's network rules.
func ipListArgs(t config.Target, verb string) []string {
	args := []string{"keyvault", "network-rule", verb, "--name", t.Resource}
	if t.Kind == config.KindStorage {
		args = []string{"storage", "account", "network-rule", verb, "--account-name", t.Resource}
	}
	return append(args, "--subscription", t.Subscription, "--resource-group", t.ResourceGroup, "--only-show-errors", "--output", "json")
}

// readIPList reads t's resource: its identity, tags, and whole network rule
// set, which network-rule list would only partly show, and for a key vault
// every property, because the Azure CLI writes them all back with a rule. A
// key vault without network rules is refused: adding to it would create a
// default rule set.
func (e *Engine) readIPList(ctx context.Context, a config.ActionConfig, t config.Target) (ipList, error) {
	args := []string{"keyvault", "show", "--name", t.Resource, "--query", "{id:id,name:name,tags:tags,network:properties.networkAcls,properties:properties}"}
	if t.Kind == config.KindStorage {
		args = []string{"storage", "account", "show", "--name", t.Resource, "--query", "{id:id,name:name,tags:tags,network:networkRuleSet}"}
	}
	raw, err := e.az(ctx, a, append(args, "--subscription", t.Subscription, "--resource-group", t.ResourceGroup, "--only-show-errors", "--output", "json"))
	if err != nil {
		return ipList{}, err
	}
	var doc struct {
		ID, Name string
		Network  *struct {
			IPRules []struct {
				Storage string `json:"ipAddressOrRange"`
				Vault   string `json:"value"`
			} `json:"ipRules"`
		} `json:"network"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return ipList{}, fmt.Errorf("%s %s: invalid Azure JSON: %w", t.Kind, t.Resource, err)
	}
	if !strings.EqualFold(doc.ID, expectedResourceID(t)) || !strings.EqualFold(doc.Name, t.Resource) {
		return ipList{}, fmt.Errorf("%s %s: Azure resource identity does not match the profile", t.Kind, t.Resource)
	}
	if doc.Network == nil {
		return ipList{}, fmt.Errorf("%s %s: no network rules to keep; configure its firewall in Azure first", t.Kind, t.Resource)
	}
	l := ipList{raw: raw, entries: []string{}}
	for _, r := range doc.Network.IPRules {
		l.entries = append(l.entries, r.Storage+r.Vault)
	}
	return l, nil
}

// readIPLists reads every list target of a, by target ID.
func (e *Engine) readIPLists(ctx context.Context, a config.ActionConfig) (map[string]ipList, error) {
	lists := map[string]ipList{}
	for _, t := range a.Targets {
		if t.IPList() {
			l, err := e.readIPList(ctx, a, t)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", t.ID, err)
			}
			lists[t.ID] = l
		}
	}
	return lists, nil
}

// listsConverged rereads every list target and reports whether each is in
// line with reg. A write from a watcher with an older registry can land
// after this pass's verification without changing any record.
func (e *Engine) listsConverged(ctx context.Context, a config.ActionConfig, reg deviceRegistry) (bool, error) {
	for _, t := range a.Targets {
		if !t.IPList() {
			continue
		}
		l, err := e.readIPList(ctx, a, t)
		if err != nil {
			return false, err
		}
		if remove, add := planIPList(l.entries, reg.activeIPs(), reg.removableIPs()); len(remove)+len(add) > 0 {
			return false, nil
		}
	}
	return true, nil
}

// covered reports whether one of entries, a single address or a range,
// allows ip. The Azure CLI does not add an address a range already covers.
func covered(entries []string, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry string) bool {
		if p, err := netip.ParsePrefix(entry); err == nil {
			return p.Contains(addr)
		}
		return entry == ip
	})
}

// planIPList returns the entries of before to remove and the addresses to
// add: deviceSources' rule for a list whose entries carry no notation of
// their own. Removal goes by address, as the CLI's does.
func planIPList(before, active, known []string) (remove, add []string) {
	var kept []string
	for _, entry := range before {
		ip, err := singleIP(entry)
		if err == nil && containsIP(known, ip) && !containsIP(active, ip) {
			remove = append(remove, entry)
		} else {
			kept = append(kept, entry)
		}
	}
	for _, ip := range active {
		if !covered(kept, ip) && !containsIP(add, ip) {
			add = append(add, ip)
		}
	}
	return remove, add
}

// listAddresses returns entries with each single address in one notation, so
// that lists compare by address.
func listAddresses(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if ip, err := singleIP(entry); err == nil {
			entry = ip
		}
		out = append(out, entry)
	}
	return out
}

// immutableIPList is a resource document without its IP entries and a key
// vault's provisioning state.
func immutableIPList(raw []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if n, ok := m["network"].(map[string]any); ok {
		delete(n, "ipRules")
	}
	if p, ok := m["properties"].(map[string]any); ok {
		delete(p, "provisioningState")
		if n, ok := p["networkAcls"].(map[string]any); ok {
			delete(n, "ipRules")
		}
	}
	return m
}

// retainedInList returns the addresses of p's retired identity that after
// keeps only because a skipped record protects them (see retainedRetiredIPs).
func retainedInList(reg deviceRegistry, p devicePass, after []string) []string {
	if p.mode != modeRetire {
		return nil
	}
	var retained []string
	for _, entry := range after {
		if containsIP(reg.Histories[p.retired], entry) && containsIP(reg.Protected, entry) && !containsIP(reg.activeIPs(), entry) {
			retained = append(retained, entry)
		}
	}
	return retained
}

// reconcileDeviceList brings t's list in line with reg (see planIPList),
// adding before it removes so that an interruption never takes away an
// address that is still needed. It plans from this pass's read in reg.Lists
// when there is one. Under modeRetire it also reports an address of the
// retired identity that a skipped record keeps allowed.
func (e *Engine) reconcileDeviceList(ctx context.Context, name string, a config.ActionConfig, t config.Target, reg deviceRegistry, p devicePass) error {
	l, ok := reg.Lists[t.ID]
	if !ok {
		var err error
		if l, err = e.readIPList(ctx, a, t); err != nil {
			return err
		}
	}
	if p.mode == modeRetire {
		p.retiredIPs = reg.Histories[p.retired]
	}
	before := l.entries
	// An entry the last write planned to keep, other than an owned address,
	// must still be there: its loss needs inspection, not a new plan that
	// would supersede the evidence.
	if pending := e.pendingWrite(name, expectedResourceID(t)+"#"); pending != nil {
		for _, entry := range pending.AfterSources {
			if !containsIP(reg.removableIPs(), entry) && !covered(listAddresses(before), entry) && !slices.Contains(listAddresses(before), entry) {
				return errors.New("pending write lost an unrelated entry; inspect the list before reconciling")
			}
		}
	}
	remove, add := planIPList(before, reg.activeIPs(), reg.removableIPs())
	if len(before)+len(add) > ipListLimit(t) {
		return fmt.Errorf("adding %v would exceed Azure's limit of %d entries; remove unused entries first", add, ipListLimit(t))
	}
	after := listAddresses(slices.Concat(slices.DeleteFunc(slices.Clone(before), func(entry string) bool { return slices.Contains(remove, entry) }), add))
	var retained error
	if ips := retainedInList(reg, p, after); len(ips) > 0 {
		e.Log.Log("retired_address_retained", map[string]any{"action": name, "target": t.ID, "identity": p.retired, "ips": ips})
		retained = fmt.Errorf("%s: %v stays allowed because a registry record that cannot be read mentions it; inspect the device_record_skipped records, then retry retirement", p.retired, ips)
	}
	if len(remove)+len(add) > 0 {
		if err := e.writeDeviceList(ctx, name, a, t, l.raw, listAddresses(before), after, remove, add, p); err != nil || !e.Apply {
			return errors.Join(err, retained)
		}
	}
	if retained != nil {
		return retained
	}
	sources := after
	if covered(after, p.desired) {
		sources = []string{p.desired}
	}
	return e.deviceRuleReceipt(name, a, t, sources, p)
}

// writeDeviceList sends a planned list change under a durable intent, after
// a fresh read confirms the plan's preimage, and verifies it by reading back.
func (e *Engine) writeDeviceList(ctx context.Context, name string, a config.ActionConfig, t config.Target, raw []byte, before, after, remove, add []string, p devicePass) error {
	fresh, err := e.readIPList(ctx, a, t)
	if err != nil {
		return err
	}
	if !slices.Equal(listAddresses(fresh.entries), before) || !reflect.DeepEqual(immutableIPList(raw), immutableIPList(fresh.raw)) {
		return errors.New("network rules changed during planning; retry")
	}
	placed := []string{e.appliedIP(name, t.ID)}
	if pending := e.pendingWrite(name, expectedResourceID(t)+"#"); pending != nil {
		placed = append(placed, pending.AfterSources...)
	}
	unplaced, err := e.unplacedRemovals(name, expectedResourceID(t), before, after, placed)
	if err != nil {
		return err
	}
	var retired []string
	if p.mode == modeRetire {
		mine := func(ip string) bool { return containsIP(p.retiredIPs, ip) }
		retired = slices.DeleteFunc(removedIPs(before, after), func(ip string) bool { return !mine(ip) })
		unplaced = slices.DeleteFunc(unplaced, mine)
	}
	if !e.Apply {
		fields := map[string]any{"target": t.ID, "add": add, "remove": remove}
		if len(unplaced) > 0 {
			fields["unplaced_removals"] = unplaced
		}
		e.Log.Log("would_reconcile_device_list", fields)
		return nil
	}
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusDeviceIntent, Target: t.ID, ResourceID: expectedResourceID(t), IP: p.desired, BeforeSources: before, AfterSources: after})
	if err != nil {
		return err
	}
	if len(add) > 0 {
		if _, err = e.az(ctx, a, append(ipListArgs(t, "add"), append([]string{"--ip-address"}, add...)...)); err != nil {
			return err
		}
	}
	if len(remove) > 0 {
		if _, err = e.az(ctx, a, append(ipListArgs(t, "remove"), append([]string{"--ip-address"}, remove...)...)); err != nil {
			return err
		}
	}
	got, err := e.readIPList(ctx, a, t)
	if err != nil {
		return fmt.Errorf("list updated, verification failed: %w", err)
	}
	if !sameStrings(listAddresses(got.entries), after) || !reflect.DeepEqual(immutableIPList(raw), immutableIPList(got.raw)) {
		return errors.New("network rule read-back changed other entries or settings; inspect before retrying")
	}
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	e.Log.Log("device_list_reconciled", map[string]any{"target": t.ID, "added": add, "removed": remove})
	if len(retired) > 0 {
		e.Log.Log("retired_address_removed", map[string]any{"action": name, "target": t.ID, "identity": p.retired, "ips": retired})
	}
	e.logUnplacedRemovals(name, t.ID, unplaced)
	return nil
}
