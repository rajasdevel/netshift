package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// deviceMode says why device rules are being reconciled.
type deviceMode int

const (
	// modeWatch keeps rules current. A missing NSG rule is an error: watch
	// never recreates one.
	modeWatch deviceMode = iota
	// modeEnroll is explicit enrollment or activation, which may restore a
	// missing NSG rule from its reviewed template.
	modeEnroll
	// modeRetire is cleanup under a retirement marker. A missing rule leaves
	// nothing to remove, and other identities' unusable records are skipped
	// instead of blocking the revocation.
	modeRetire
)

// loadDevices reads every registry NSG and refuses any unusable record.
func (e *Engine) loadDevices(ctx context.Context, a config.ActionConfig) (deviceRegistry, error) {
	reg, err := e.readRegistry(ctx, a, e.Config.Identity)
	if err == nil {
		err = reg.strict()
	}
	return reg, err
}

// readRegistry reads every registry NSG. Only owner's records must be usable;
// the caller decides whether others' skipped records are acceptable.
func (e *Engine) readRegistry(ctx context.Context, a config.ActionConfig, owner string) (deviceRegistry, error) {
	reg := newRegistry()
	for _, t := range config.NSGGroups(a) {
		n, err := e.readSharedNSG(ctx, a, t)
		if err != nil {
			return reg, err
		}
		if err = reg.addNSG(n, a, owner); err != nil {
			return reg, err
		}
	}
	reg.settle()
	return reg, nil
}

// ownDeviceHistory is this identity's ownership evidence: its registry
// history, the legacy or seed configuration it alone may adopt, its verified
// local receipts and own tag values (newest first), and its state receipts.
func (e *Engine) ownDeviceHistory(name string, a config.ActionConfig, reg deviceRegistry) ([]string, error) {
	id := e.Config.Identity
	ips := append([]string{}, reg.Histories[id]...)
	legacy := id == a.Devices.LegacyIdentity
	seedOwner := legacy || id == a.Devices.SeedIdentity
	if legacy {
		ips = append(ips, reg.LegacyIPs...)
	}
	if seedOwner {
		ips = append(ips, e.Config.KnownIPs...)
	}
	if e.StatePath != "" {
		ownTag := deviceTag(a, id, false)
		recent, err := recentHistoryIPs(store.HistoryPath(e.StatePath), ownershipWindow, func(r store.HistoryRecord, add func(string)) {
			if r.Action != name || (r.Identity != id && !(legacy && r.Identity == "")) {
				return
			}
			if provesOwnership(r.Status) {
				add(r.IP)
				if r.Identity == "" && legacy {
					for _, ip := range r.RemovedIPs {
						add(ip)
					}
				}
			}
			if strings.EqualFold(r.Tag, ownTag) && r.AfterValue != "" {
				if d, err := parseDevice(r.AfterValue); err == nil && d.Identity == id {
					for _, ip := range d.IPs {
						add(ip)
					}
				}
			}
		})
		if err != nil {
			return nil, err
		}
		ips = append(ips, recent...)
	}
	if e.State.Identity == id {
		for _, t := range a.Targets {
			s := e.State.Action(name).Target(t.ID)
			ips = append(ips, s.AppliedIP, s.PendingIP)
		}
	}
	if seedOwner {
		for _, t := range a.Targets {
			ips = append(ips, t.BootstrapIP)
			ips = append(ips, t.KnownIPs...)
		}
	}
	return uniqueIPs(ips), nil
}

// pinnedSources returns first, then every address of owned that a registry
// rule of a still allows, in rule order, except the current address of
// another active identity. Each returned address must stay in the record
// being planned. Otherwise a partial failure could leave it in a rule with no
// record listing it, and reconciliation, which removes only addresses some
// record lists, would never remove it. Another identity's current address
// needs no pin: that identity's record lists it for as long as it is there,
// and when that identity moves away it pins the address itself. Pinning it
// here would let a shared NAT or VPN egress pool fill the history limit.
func pinnedSources(reg deviceRegistry, a config.ActionConfig, id, first string, owned []string) []string {
	mine := map[string]bool{}
	for _, ip := range owned {
		mine[ip] = true
	}
	for other, d := range reg.Devices {
		if other != id && !d.Retired {
			mine[d.IPs[0]] = false
		}
	}
	pinned := []string{first}
	for _, t := range a.Targets {
		if t.Kind != config.KindNSG {
			continue
		}
		r, ok := findNSGRule(reg.NSGs[strings.ToLower(config.NSGResourceID(t))], t)
		if !ok {
			continue
		}
		for _, source := range r.sourceList() {
			if ip, err := singleIP(source); err == nil && mine[ip] {
				pinned = append(pinned, ip)
			}
		}
	}
	return uniqueIPs(pinned)
}

// makeDeviceRecord plans id's next active record for desired from reg and
// known, id's ownership evidence (see ownDeviceHistory). Its addresses are
// desired, then the pinned addresses (see pinnedSources), then the current
// record's and the rest of known, newest first, cut to history_limit and to
// the tag value limit. The revision grows only when the addresses change. It
// refuses a retired identity, and a plan that cannot keep every pinned one.
func makeDeviceRecord(reg deviceRegistry, a config.ActionConfig, id, desired string, known []string) (DeviceRecord, error) {
	old := reg.Devices[id]
	if old.Retired {
		return old, errors.New("identity is retired; explicit activation is required")
	}
	pinned := pinnedSources(reg, a, id, desired, known)
	if len(pinned) > a.Devices.HistoryLimit {
		return old, errors.New("too many owned IPs still present in NSG rules; reconcile before trimming history")
	}
	ips := uniqueIPs(append(append(pinned, old.IPs...), known...))
	d := DeviceRecord{Version: 2, Identity: id, IPs: ips, Revision: old.Revision + 1}
	if d.Revision == 0 {
		return old, errors.New("device revision overflow")
	}
	raw, err := encodeDevice(d, a.Devices.HistoryLimit)
	if err != nil {
		return d, err
	}
	d, err = parseDevice(raw)
	if err != nil {
		return d, err
	}
	for _, ip := range pinned {
		if !containsIP(d.IPs, ip) {
			return d, errors.New("tag size would discard an IP still in a managed rule")
		}
	}
	// A version-2 record always lists at least one IP, so nil never meets empty.
	if old.Version == 2 && slices.Equal(old.IPs, d.IPs) {
		d.Revision = old.Revision
	}
	return d, nil
}

// containsIP reports whether ips lists ip.
func containsIP(ips []string, ip string) bool {
	return slices.Contains(ips, ip)
}

// containsAll reports whether have lists every address in need.
func containsAll(have, need []string) bool {
	for _, ip := range need {
		if !slices.Contains(have, ip) {
			return false
		}
	}
	return true
}

// sameRecord reports whether x and y are the same device record.
func sameRecord(x, y DeviceRecord) bool {
	return x.Version == y.Version && x.Identity == y.Identity && x.Revision == y.Revision && x.Retired == y.Retired && slices.Equal(x.IPs, y.IPs)
}

// beginDeviceWrite saves the intent of one external device write, in its
// shared-state slot and in history, before the write is sent. Every external
// mutation has a synced intent and a verified receipt; the slot also survives
// process termination between those two steps.
func (e *Engine) beginDeviceWrite(name string, r store.HistoryRecord) (store.HistoryRecord, error) {
	r.Action = name
	r.At = e.now()
	if r.Identity == "" {
		r.Identity = e.Config.Identity
	}
	r.OperationID = store.OperationID()
	if !e.Apply {
		return r, nil
	}
	s := e.sharedState(name, r.ResourceID+"#"+r.Tag)
	if s.Pending != nil {
		// Never replace an unresolved intent silently: its write may still land,
		// and the audit trail must show which plan replaced it.
		previous := *s.Pending
		previous.Status = statusDeviceSuperseded
		if err := e.record(previous); err != nil {
			return r, err
		}
	}
	s.Pending = &r
	if err := e.save(); err != nil {
		return r, err
	}
	return r, e.record(r)
}

// finishDeviceWrite records r verified and closes its slot.
func (e *Engine) finishDeviceWrite(name string, r store.HistoryRecord) error {
	if !e.Apply {
		return nil
	}
	r.Status = statusDeviceVerified
	if err := e.record(r); err != nil {
		return err
	}
	s := e.sharedState(name, r.ResourceID+"#"+r.Tag)
	s.Pending = nil
	s.Value = r.AfterValue
	s.VerifiedAt = e.now()
	return e.save()
}

// supersedeDeviceWrite closes the pending intent in slot key without its
// write: the resource already holds value, so nothing of that plan remains
// to do. The intent stays in the audit trail.
func (e *Engine) supersedeDeviceWrite(name, key, value string) error {
	if !e.Apply {
		return nil
	}
	s := e.sharedState(name, key)
	if s.Pending == nil {
		return nil
	}
	r := *s.Pending
	r.Status = statusDeviceSuperseded
	if err := e.record(r); err != nil {
		return err
	}
	s.Pending, s.Value, s.VerifiedAt = nil, value, e.now()
	return e.save()
}

// tagWrite is one change to a registry tag on one NSG. An empty value
// deletes the tag.
type tagWrite struct {
	key, value, owner string
	mode              deviceMode
	// seen is this pass's registry read of the NSG, if any. When it already
	// shows value and no write is pending, there is nothing to write and the
	// fresh read is skipped; the convergence reloads still see later changes.
	seen *azureNSG
}

// writeDeviceTag reads the NSG fresh, refuses an unsafe change, then writes
// the tag with a durable intent and verifies it by reading back.
func (e *Engine) writeDeviceTag(ctx context.Context, name string, a config.ActionConfig, t config.Target, w tagWrite) error {
	if w.seen != nil {
		if _, current, err := tagValue(w.seen.Tags, w.key); err == nil && current == w.value && e.pendingWrite(name, w.seen.ID+"#"+w.key) == nil {
			return nil
		}
	}
	n, err := e.readSharedNSG(ctx, a, t)
	if err != nil {
		return err
	}
	actualKey, before, err := tagValue(n.Tags, w.key)
	if err != nil {
		return err
	}
	checked := newRegistry()
	if err = checked.addNSG(n, a, w.owner); err != nil {
		return err
	}
	if w.mode != modeRetire {
		if err = checked.strict(); err != nil {
			return err
		}
	}
	if before == w.value {
		return e.reconcileDeviceIntent(name, n.ID+"#"+w.key, w.value)
	}
	if err = guardTagWrite(a, n, w, before); err != nil {
		return err
	}
	if !e.Apply {
		e.Log.Log("would_update_device_tag", map[string]any{"nsg": t.NSG, "identity": w.owner, "tag": w.key, "before": before, "after": w.value})
		return nil
	}
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusMetadataIntent, Identity: w.owner, Target: "registry", ResourceID: n.ID, Tag: actualKey, BeforeValue: before, AfterValue: w.value})
	if err != nil {
		return err
	}
	operation := "Merge"
	tag := actualKey + "=" + w.value
	if w.value == "" {
		operation = "Delete"
		tag = actualKey + "=" + before
	}
	args := []string{"tag", "update", "--subscription", t.Subscription, "--resource-id", n.ID, "--operation", operation, "--tags", tag, "--only-show-errors", "--output", "json"}
	if _, err = e.az(ctx, a, args); err != nil {
		return err
	}
	after, err := e.readSharedNSG(ctx, a, t)
	if err != nil {
		return err
	}
	_, got, err := tagValue(after.Tags, actualKey)
	if err != nil {
		return err
	}
	if got != w.value {
		return errors.New("device tag read-back mismatch; retry with fresh registry")
	}
	// Other writers can update their own keys concurrently. Merge/Delete never
	// sends their keys, so do not reject legitimate independent device updates.
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	e.Log.Log("device_registry_updated", map[string]any{"nsg": t.NSG, "identity": w.owner, "tag": w.key})
	return nil
}

// guardTagWrite refuses a tag change that the fresh read n shows to be unsafe.
func guardTagWrite(a config.ActionConfig, n azureNSG, w tagWrite, before string) error {
	active := strings.EqualFold(w.key, deviceTag(a, w.owner, false))
	retired := strings.EqualFold(w.key, deviceTag(a, w.owner, true))
	if w.value != "" && before == "" {
		if err := checkTagSlots(n, 1, retired); err != nil {
			return err
		}
	}
	_, marker, err := tagValue(n.Tags, deviceTag(a, w.owner, true))
	if err != nil {
		return err
	}
	switch {
	case retired && before != "" && w.value != "":
		old, err := parseDevice(before)
		if err != nil {
			return err
		}
		next, err := parseDevice(w.value)
		if err != nil {
			return err
		}
		// Markers only grow. Two retirers can write different markers at one
		// revision; a write may then extend the other's, never shrink it.
		if old.Revision > next.Revision || old.Revision == next.Revision && !containsAll(next.IPs, old.IPs) {
			return errors.New("retirement marker changed during planning; retry")
		}
	case active && w.value != "":
		if marker != "" {
			return errors.New("identity was retired during update")
		}
		next, err := parseDevice(w.value)
		if err != nil {
			return err
		}
		if before != "" {
			old, err := parseDevice(before)
			if err != nil {
				return err
			}
			if old.Identity != w.owner || old.Revision > next.Revision || (old.Revision == next.Revision && before != w.value) {
				return errors.New("device record changed during planning; retry")
			}
		}
	case active && w.mode == modeRetire && before != "":
		// Retirement drops the active record only while the marker still lists
		// every address in it; otherwise those addresses would be forgotten.
		if marker == "" {
			return errors.New("retirement marker disappeared before the active record was removed; retry")
		}
		tomb, err := parseDevice(marker)
		if err != nil {
			return err
		}
		old, err := parseDevice(before)
		if err != nil {
			return err
		}
		if !containsAll(tomb.IPs, old.IPs) {
			return fmt.Errorf("the active record of %s lists addresses its retirement marker lacks; retry retirement", w.owner)
		}
	}
	return nil
}

// checkTagSlots refuses adding added tags to n when that would take the last
// of Azure's tag slots, which stays free for a retirement marker: without it
// an enrolled device could never be retired. A marker itself (marker set) may
// take that slot, but no tag ever replaces an unrelated one.
func checkTagSlots(n azureNSG, added int, marker bool) error {
	switch total := len(n.Tags) + added; {
	case total > maxNSGTags:
		return errors.New("NSG tag limit reached; no unrelated tag will be replaced")
	case total == maxNSGTags && !marker:
		return fmt.Errorf("NSG %s has %d tags; NetShift needs %d more and keeps one of Azure's %d tag slots free for a retirement marker; remove an unused tag first", n.Name, len(n.Tags), added, maxNSGTags)
	}
	return nil
}

// reconcileDeviceIntent settles the pending write of tag slot key, which now
// holds value. A write of value succeeded before an interruption. A write of
// anything else was rejected or overwritten and the wanted value changed back
// since (say, the IP flipped back), so nothing of it remains to do.
func (e *Engine) reconcileDeviceIntent(name, key, value string) error {
	pending := e.pendingWrite(name, key)
	if pending == nil {
		return nil
	}
	if pending.AfterValue == value {
		return e.finishDeviceWrite(name, *pending)
	}
	return e.supersedeDeviceWrite(name, key, value)
}

// findNSGRule finds the target's rule. Azure resource names ignore case and
// rule create is an upsert, so a name that differs only in case counts as
// present; identity checks then refuse it instead of overwriting it.
func findNSGRule(n azureNSG, t config.Target) (azureRule, bool) {
	i := slices.IndexFunc(n.Rules, func(r azureRule) bool { return strings.EqualFold(r.Name, t.Rule) })
	if i < 0 {
		return azureRule{}, false
	}
	return n.Rules[i], true
}

// preflightDeviceNSGs checks every registry rule in reg before any write: it
// must exist in its reviewed shape, except that enrollment may restore it.
func (e *Engine) preflightDeviceNSGs(a config.ActionConfig, reg deviceRegistry, mode deviceMode) error {
	for _, t := range a.Targets {
		if t.Kind != config.KindNSG {
			continue
		}
		r, found := findNSGRule(reg.NSGs[strings.ToLower(config.NSGResourceID(t))], t)
		if !found {
			if mode == modeEnroll {
				continue
			}
			return fmt.Errorf("%s missing; review and use devices enroll to restore its template", t.ID)
		}
		if err := validateDeviceNSG(r, t); err != nil {
			return fmt.Errorf("%s: %w", t.ID, err)
		}
	}
	return nil
}

// devicePass says what one reconciliation of the registry rules is for.
type devicePass struct {
	mode deviceMode
	// desired is this identity's address. A rule's receipt is saved only
	// when the reconciled rule allows desired; outside retirement it must.
	desired string
	// retired is the identity being retired under modeRetire. Removing one
	// of retiredIPs, its addresses, is logged as a retirement, not as an
	// unplaced removal.
	retired    string
	retiredIPs []string
}

// reconcileDeviceNSG brings t's rule in line with reg: every active
// identity's current address present, every other address that a registry
// record lists and no unusable record mentions removed, and every unrelated
// source kept (see deviceSources). A missing rule is restored from its
// template only under modeEnroll; under modeRetire, or with no active
// identity left, it has nothing to remove. A rule already in line settles
// its pending intent, if that intent lost no unrelated source.
func (e *Engine) reconcileDeviceNSG(ctx context.Context, name string, a config.ActionConfig, t config.Target, reg deviceRegistry, p devicePass) error {
	r, found := findNSGRule(reg.NSGs[strings.ToLower(config.NSGResourceID(t))], t)
	active := reg.activeIPs()
	if !found {
		if p.mode == modeRetire || len(active) == 0 {
			// A rule that is gone has nothing left to remove.
			return e.reconcileDeletedIntent(name, expectedResourceID(t), p.mode)
		}
		if p.mode != modeEnroll {
			return fmt.Errorf("%s missing; explicit devices enroll is required to restore it", t.ID)
		}
		return e.createDeviceNSG(ctx, name, a, t, active, p)
	}
	if err := validateDeviceNSG(r, t); err != nil {
		return err
	}
	if p.mode == modeRetire {
		p.retiredIPs = reg.Histories[p.retired]
	}
	known := reg.removableIPs()
	before := r.sourceList()
	after := deviceSources(before, active, known)
	if !sameStrings(before, after) {
		return e.replaceDeviceSources(ctx, name, a, t, before, after, active, p)
	}
	if pending := e.pendingWrite(name, expectedResourceID(t)+"#"); pending != nil {
		for _, source := range pending.AfterSources {
			ip, parseErr := singleIP(source)
			if parseErr == nil && containsIP(known, ip) {
				continue
			}
			if !containsIP(before, source) {
				return errors.New("pending write lost an unrelated source; inspect before reconciling")
			}
		}
	}
	return e.deviceRuleReceipt(name, a, t, after, p)
}

// replaceDeviceSources writes a registry rule's reconciled source list after
// a fresh read confirms the planned preimage, deleting the rule when no
// source remains, and verifies the result.
func (e *Engine) replaceDeviceSources(ctx context.Context, name string, a config.ActionConfig, t config.Target, before, after, active []string, p devicePass) error {
	raw, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	fresh, err := decodeRule(raw)
	if err != nil {
		return err
	}
	if err = validateDeviceNSG(fresh, t); err != nil {
		return err
	}
	if !sameStrings(fresh.sourceList(), before) {
		return errors.New("NSG sources changed during planning; retry")
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
		// Removing the retired identity's own addresses is the point of
		// retirement, not a removal to review.
		mine := func(ip string) bool { return containsIP(p.retiredIPs, ip) }
		retired = slices.DeleteFunc(removedIPs(before, after), func(ip string) bool { return !mine(ip) })
		unplaced = slices.DeleteFunc(unplaced, mine)
	}
	if !e.Apply {
		fields := map[string]any{"target": t.ID, "before": before, "after": after}
		if len(unplaced) > 0 {
			fields["unplaced_removals"] = unplaced
		}
		if len(retired) > 0 {
			fields["retired_removals"] = retired
		}
		e.Log.Log("would_reconcile_device_sources", fields)
		return nil
	}
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusDeviceIntent, Target: t.ID, ResourceID: expectedResourceID(t), IP: p.desired, BeforeSources: before, AfterSources: after})
	if err != nil {
		return err
	}
	if len(after) == 0 {
		err = e.deleteLastOwnerNSG(ctx, a, t)
	} else {
		err = e.updateDeviceSources(ctx, a, t, raw, after)
	}
	if err != nil {
		return err
	}
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	e.Log.Log("device_sources_reconciled", map[string]any{"target": t.ID, "active_ips": active})
	if len(retired) > 0 {
		e.Log.Log("retired_address_removed", map[string]any{"action": name, "target": t.ID, "identity": p.retired, "ips": retired})
	}
	e.logUnplacedRemovals(name, t.ID, unplaced)
	return e.deviceRuleReceipt(name, a, t, after, p)
}

// deleteLastOwnerNSG removes a rule whose last owner retired: there is no
// safe empty Allow rule.
func (e *Engine) deleteLastOwnerNSG(ctx context.Context, a config.ActionConfig, t config.Target) error {
	if _, err := e.az(ctx, a, targetArgs(t, "delete")); err != nil {
		return err
	}
	n, err := e.readSharedNSG(ctx, a, t)
	if err != nil {
		return err
	}
	if _, ok := findNSGRule(n, t); ok {
		return errors.New("NSG rule still exists after retirement")
	}
	return nil
}

// updateDeviceSources sets t's sources to after and verifies, by reading
// back, that only the sources changed.
func (e *Engine) updateDeviceSources(ctx context.Context, a config.ActionConfig, t config.Target, before []byte, after []string) error {
	args := append(targetArgs(t, "update"), "--source-address-prefixes")
	args = append(args, after...)
	if _, err := e.az(ctx, a, args); err != nil {
		return err
	}
	raw, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	got, err := decodeRule(raw)
	if err != nil {
		return err
	}
	if err = validateDeviceNSG(got, t); err != nil {
		return err
	}
	if !sameStrings(got.sourceList(), after) || !reflect.DeepEqual(immutableRule(before), immutableRule(raw)) {
		return errors.New("NSG read-back changed sources or another rule field; inspect before retrying")
	}
	return nil
}

// appliedIP is a target's last receipt address, read without creating state.
func (e *Engine) appliedIP(name, target string) string {
	if a := e.State.Actions[name]; a != nil {
		if s := a.Targets[target]; s != nil {
			return s.AppliedIP
		}
	}
	return ""
}

// deviceRuleReceipt finishes a registry rule that a read or write just showed
// holding sources. When they allow p.desired, it saves the target's receipt
// for p.desired. Otherwise no receipt may claim that address: under
// retirement only the rule's pending intent is settled, since retirement may
// have removed this identity's own address; outside it, this identity's
// verified record should have put the address there, so its absence is an
// error to retry from a fresh read.
func (e *Engine) deviceRuleReceipt(name string, a config.ActionConfig, t config.Target, sources []string, p devicePass) error {
	if slices.ContainsFunc(sources, func(source string) bool {
		ip, err := singleIP(source)
		return err == nil && ip == p.desired
	}) {
		return e.deviceTargetReceipt(name, a, t, p.desired)
	}
	if p.mode != modeRetire {
		return fmt.Errorf("reconciled rule does not allow this identity's address %s; retry with a fresh registry read", p.desired)
	}
	if err := e.settleRuleIntent(name, t, p.desired); err != nil {
		return err
	}
	return e.save()
}

// deviceTargetReceipt saves that t was verified allowing ip under the current
// policy. It settles t's pending writes: the rule's device intent (see
// settleRuleIntent), and a single-IP or mapped plan left from before devices
// mode, which this verification replaces and which is recorded superseded.
func (e *Engine) deviceTargetReceipt(name string, a config.ActionConfig, t config.Target, ip string) error {
	s := e.State.Action(name).Target(t.ID)
	if s.PendingChange != nil {
		r := *s.PendingChange
		r.Status = statusSuperseded
		if err := e.record(r); err != nil {
			return err
		}
	}
	s.AppliedIP = ip
	s.PendingIP = ""
	s.PendingChange = nil
	s.HistoryInitialized = true
	s.Fingerprint = targetPolicyFingerprint(t, a)
	s.VerifiedAt = e.now()
	if err := e.settleRuleIntent(name, t, ip); err != nil {
		return err
	}
	return e.save()
}

// settleRuleIntent closes the pending device intent of t's rule after a read
// showed the rule in its reconciled state: a retry can discover that an
// interrupted write already succeeded. The intent's original before/after
// record is kept, reconciled when it was for ip and superseded otherwise; a
// delete intent is always superseded, since the rule still exists.
func (e *Engine) settleRuleIntent(name string, t config.Target, ip string) error {
	key := expectedResourceID(t) + "#"
	pending := e.pendingWrite(name, key)
	if pending == nil {
		return nil
	}
	r := *pending
	r.Status = statusDeviceReconciled
	if pending.Status == statusDeviceDeleteIntent || (r.IP != "" && r.IP != ip) {
		r.Status = statusDeviceSuperseded
	}
	if err := e.record(r); err != nil {
		return err
	}
	e.sharedState(name, key).Pending = nil
	return nil
}

// createDeviceNSG restores t's missing rule from its reviewed template with
// active as its sources, and verifies it. Only explicit enrollment calls it:
// watch never recreates a missing rule.
func (e *Engine) createDeviceNSG(ctx context.Context, name string, a config.ActionConfig, t config.Target, active []string, p devicePass) error {
	n, err := e.readSharedNSG(ctx, a, t)
	if err != nil {
		return err
	}
	if _, ok := findNSGRule(n, t); ok {
		return errors.New("rule appeared during enrollment; retry")
	}
	if !e.Apply {
		e.Log.Log("would_restore_nsg_template", map[string]any{"target": t.ID, "active_ips": active})
		return nil
	}
	tpl := t.Template
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusDeviceCreateIntent, Target: t.ID, ResourceID: expectedResourceID(t), IP: p.desired, AfterSources: active})
	if err != nil {
		return err
	}
	args := append(targetArgs(t, "create"), "--priority", fmt.Sprint(tpl.Priority), "--access", "Allow", "--direction", "Inbound", "--protocol", tpl.Protocol, "--source-address-prefixes")
	args = append(args, active...)
	args = append(args, "--source-port-ranges")
	args = append(args, tpl.SourcePorts...)
	args = append(args, "--destination-address-prefixes")
	args = append(args, tpl.Destinations...)
	args = append(args, "--destination-port-ranges")
	args = append(args, tpl.Ports...)
	if tpl.Description != "" {
		// One argument, so a description that starts with "-" is not read as
		// an option. validateDevices refuses one that starts with "@".
		args = append(args, "--description="+tpl.Description)
	}
	if _, err = e.az(ctx, a, args); err != nil {
		return err
	}
	raw, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	r, err := decodeRule(raw)
	if err != nil {
		return err
	}
	if err = validateDeviceNSG(r, t); err != nil {
		return err
	}
	got := []string{}
	for _, source := range r.sourceList() {
		ip, err := singleIP(source)
		if err != nil {
			return err
		}
		got = append(got, ip)
	}
	if !sameStrings(got, active) || r.Description != tpl.Description {
		return errors.New("restored NSG rule does not match its reviewed template")
	}
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	return e.deviceRuleReceipt(name, a, t, active, p)
}

// runDevices brings this identity's registry record and every device rule to
// desired. It plans from one registry read, publishes the record, and then
// reconciles in up to three passes, each of which reloads the registry. It
// returns errIdentityRetired, after cleanup, when the identity is retired.
func (e *Engine) runDevices(ctx context.Context, name string, a config.ActionConfig, desired string, enroll bool) error {
	if _, err := config.PublicIPv4(desired); err != nil {
		return err
	}
	mode := modeWatch
	if enroll {
		mode = modeEnroll
	}
	id := e.Config.Identity
	reg, err := e.readRegistry(ctx, a, id)
	if err != nil {
		return err
	}
	// Own records are always strict, so a retirement is observed even while
	// another identity's record is unusable; anything else needs all of them.
	if reg.Devices[id].Retired {
		return e.observeRetirement(ctx, name, a, id)
	}
	if err = reg.strict(); err != nil {
		return err
	}
	if len(reg.LegacyIPs) > 0 && id != a.Devices.LegacyIdentity {
		return errors.New("legacy shared history must first be migrated by " + a.Devices.LegacyIdentity)
	}
	known, err := e.ownDeviceHistory(name, a, reg)
	if err != nil {
		return err
	}
	d, err := makeDeviceRecord(reg, a, id, desired, known)
	if err != nil {
		return err
	}
	if err = e.preflightDeviceNSGs(a, reg, mode); err != nil {
		return err
	}
	if err = e.preflightDevicePG(ctx, a, id, desired, known); err != nil {
		return err
	}
	if err = e.publishDeviceRecord(ctx, name, a, reg, d); err != nil {
		return err
	}
	if !e.Apply {
		reg.Devices[id] = d
		reg.Histories[id] = uniqueIPs(slices.Concat(known, d.IPs))
	}
	return e.convergeDevices(ctx, name, a, reg, d, known, mode)
}

// publishDeviceRecord writes this identity's record, and the legacy migration
// marker for the legacy owner, to every registry NSG. reg is this pass's
// read: a tag it already shows at the wanted value is not read again.
func (e *Engine) publishDeviceRecord(ctx context.Context, name string, a config.ActionConfig, reg deviceRegistry, d DeviceRecord) error {
	raw, err := encodeDevice(d, a.Devices.HistoryLimit)
	if err != nil {
		return err
	}
	writes := []tagWrite{{key: deviceTag(a, d.Identity, false), value: raw, owner: d.Identity}}
	if d.Identity == a.Devices.LegacyIdentity && a.Devices.LegacyTag != "" {
		marker, err := json.Marshal(newLegacyMarker(a))
		if err != nil {
			return err
		}
		writes = append(writes, tagWrite{key: a.Devices.LegacyTag, value: string(marker), owner: d.Identity})
	}
	// Check every NSG's tag slots for every new tag first, so that a refusal
	// leaves no partial publish. writeDeviceTag checks each write again.
	for _, t := range config.NSGGroups(a) {
		n, ok := reg.NSGs[strings.ToLower(config.NSGResourceID(t))]
		if !ok {
			continue
		}
		added := 0
		for _, w := range writes {
			if _, current, err := tagValue(n.Tags, w.key); err == nil && current == "" {
				added++
			}
		}
		if added > 0 {
			if err := checkTagSlots(n, added, false); err != nil {
				return err
			}
		}
	}
	for _, w := range writes {
		for _, t := range config.NSGGroups(a) {
			write := w
			if seen, ok := reg.NSGs[strings.ToLower(config.NSGResourceID(t))]; ok {
				write.seen = &seen
			}
			if err = e.writeDeviceTag(ctx, name, a, t, write); err != nil {
				return err
			}
		}
	}
	return nil
}

// convergeDevices reconciles every target to published, this identity's
// record, from a fresh registry read, and stops once a second read shows
// nothing changed meanwhile. The reloads are the safety mechanism against
// concurrent writers; none may be skipped.
//
// Each reload must still show published. A late earlier write, a duplicate
// installation, or a person can replace it after its read-back, and
// reconciling from the replacement would drop this identity's address. The
// pass then publishes it again instead, within the same bounded passes; the
// write guard refuses to overwrite a newer record.
func (e *Engine) convergeDevices(ctx context.Context, name string, a config.ActionConfig, reg deviceRegistry, published DeviceRecord, known []string, mode deviceMode) error {
	id := e.Config.Identity
	desired := published.IPs[0]
	p := devicePass{mode: mode, desired: desired}
	reload := func() (deviceRegistry, error) {
		r, err := e.readRegistry(ctx, a, id)
		if err != nil {
			return r, err
		}
		r.Histories[id] = uniqueIPs(slices.Concat(r.Histories[id], known))
		return r, nil
	}
	for range 3 {
		if e.Apply {
			var err error
			if reg, err = reload(); err != nil {
				return err
			}
		}
		if reg.Devices[id].Retired {
			return e.observeRetirement(ctx, name, a, id)
		}
		if err := reg.strict(); err != nil {
			return err
		}
		if current := reg.Devices[id]; !sameRecord(current, published) {
			e.Log.Log("device_record_republished", map[string]any{"identity": id, "found_revision": current.Revision, "revision": published.Revision})
			if err := e.publishDeviceRecord(ctx, name, a, reg, published); err != nil {
				return err
			}
			continue
		}
		for _, t := range a.Targets {
			var err error
			if t.Kind == config.KindNSG {
				err = e.reconcileDeviceNSG(ctx, name, a, t, reg, p)
			} else {
				err = e.reconcileDevicePG(ctx, name, a, t, id, desired, known)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", t.ID, err)
			}
		}
		if !e.Apply {
			return nil
		}
		after, err := reload()
		if err == nil {
			err = after.strict()
		}
		if err != nil {
			return err
		}
		if devicesConverged(a, reg, after) {
			return nil
		}
	}
	return errors.New("device registry changed during reconciliation; retry scheduled with fresh state")
}

// devicesConverged reports whether after, read once reconciliation finished,
// shows the same records as reg and every registry rule already reconciled.
func devicesConverged(a config.ActionConfig, reg, after deviceRegistry) bool {
	if config.Fingerprint(reg.Devices) != config.Fingerprint(after.Devices) {
		return false
	}
	for _, t := range a.Targets {
		if t.Kind != config.KindNSG {
			continue
		}
		r, ok := findNSGRule(after.NSGs[strings.ToLower(config.NSGResourceID(t))], t)
		if !ok {
			return false
		}
		sources := r.sourceList()
		if !sameStrings(sources, deviceSources(sources, after.activeIPs(), after.removableIPs())) {
			return false
		}
	}
	return true
}
