package engine

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// History record statuses. They are part of the history file format; never
// change their values.
const (
	// Single-IP and mapped targets (azureTarget).
	statusIntent     = "intent"
	statusVerified   = "verified"
	statusReconciled = "reconciled"
	statusSuperseded = "superseded"
	statusBaseline   = "baseline"
	statusFailed     = "failed"

	// Registry tag writes: the shared IP history, and a device's own tags.
	statusMetadataIntent     = "metadata_intent"
	statusMetadataVerified   = "metadata_verified"
	statusMetadataReconciled = "metadata_reconciled"
	statusMetadataSuperseded = "metadata_superseded"
	statusMetadataFailed     = "metadata_failed"

	// Per-device writes. Device-mode tag writes also finish with these.
	statusDeviceIntent       = "device_intent"
	statusDeviceCreateIntent = "device_create_intent"
	statusDeviceDeleteIntent = "device_delete_intent"
	statusDeviceVerified     = "device_verified"
	statusDeviceReconciled   = "device_reconciled"
	statusDeviceSuperseded   = "device_superseded"
)

// provesOwnership reports whether a record with this status is a verified
// receipt: a write (or, for a baseline, a read) completed while this machine
// held the record's IP, so that address was this identity's. Intents,
// superseded plans, and failures prove nothing. Every ownership reader uses
// this one set.
func provesOwnership(status string) bool {
	switch status {
	case statusVerified, statusReconciled, statusBaseline,
		statusMetadataVerified, statusMetadataReconciled,
		statusDeviceVerified, statusDeviceReconciled:
		return true
	}
	return false
}

// ownershipIPs reports a record's ownership evidence for a single-IP or
// shared-history action: the address of a verified receipt and the addresses
// that receipt verifiably replaced. It never reads before/after sources,
// which also hold other people's entries.
func ownershipIPs(r store.HistoryRecord, add func(string)) {
	if !provesOwnership(r.Status) {
		return
	}
	add(r.IP)
	for _, ip := range r.RemovedIPs {
		add(ip)
	}
}

// ownershipWindow is how many of the newest journal records can prove
// ownership. Older records are ignored.
const ownershipWindow = 100000

// recentHistoryIPs returns the addresses pick reports for the newest window
// records of the journal at path: canonical, without duplicates, newest
// record first and in pick's order within a record. That is exactly what
// walking the last window records backward and keeping each address's first
// occurrence returns, but the journal is streamed and only one entry per
// distinct address is held in memory.
func recentHistoryIPs(path string, window int, pick func(store.HistoryRecord, func(string))) ([]string, error) {
	type position struct{ record, index int }
	latest := map[string]position{}
	records := 0
	for r, err := range store.ScanHistory(path) {
		if err != nil {
			return nil, err
		}
		index := 0
		pick(r, func(ip string) {
			value, err := config.PublicIPv4(ip)
			if err != nil {
				return
			}
			// A newer record moves the address; within one record the first
			// mention wins.
			if p, ok := latest[value]; !ok || p.record < records {
				latest[value] = position{records, index}
			}
			index++
		})
		records++
	}
	ips := make([]string, 0, len(latest))
	for ip, p := range latest {
		if p.record >= records-window {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, func(x, y string) int {
		a, b := latest[x], latest[y]
		return cmp.Or(cmp.Compare(b.record, a.record), cmp.Compare(a.index, b.index))
	})
	return ips, nil
}

// lastVerifiedSources returns the source list of rule resourceID in this
// identity's newest verified receipt for it, or nil when the local history
// has none.
func (e *Engine) lastVerifiedSources(name, resourceID string) ([]string, error) {
	if e.StatePath == "" {
		return nil, nil
	}
	var last []string
	for r, err := range store.ScanHistory(store.HistoryPath(e.StatePath)) {
		if err != nil {
			return nil, err
		}
		if r.Action == name && provesOwnership(r.Status) && len(r.AfterSources) > 0 && strings.EqualFold(r.ResourceID, resourceID) && (r.Identity == "" || r.Identity == e.Config.Identity) {
			last = r.AfterSources
		}
	}
	return last, nil
}

// IPHistory is a compact record that fits ten IPv4 addresses in one Azure tag
// (256 characters). The namespace is the configured tag key; unrelated tags
// and comments are opaque.
type IPHistory struct {
	Version int      `json:"v"`
	IPs     []string `json:"ips"`
}

// uniqueIPs returns the public IPv4 addresses of ips in canonical form, once
// each, in order; anything else is dropped.
func uniqueIPs(ips []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, ip := range ips {
		if value, err := config.PublicIPv4(ip); err == nil && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

// lookupTag finds wanted among tags, ignoring case like Azure does. Two keys
// that differ only by case are an error, because either could be the one
// Azure later reports or updates.
func lookupTag(tags map[string]string, wanted string) (key, value string, found bool, err error) {
	key = wanted
	for k, v := range tags {
		if !strings.EqualFold(k, wanted) {
			continue
		}
		if found {
			return wanted, "", false, fmt.Errorf("duplicate tag keys differing only by case: %s", wanted)
		}
		key, value, found = k, v, true
	}
	return key, value, found, nil
}

// tagValue returns the stored spelling and the value of wanted, or wanted
// and "" when it is absent.
func tagValue(tags map[string]string, wanted string) (key, value string, err error) {
	key, value, _, err = lookupTag(tags, wanted)
	return key, value, err
}

// historyTag reads the shared-history tag wanted from tags: its stored
// spelling, raw value, and parsed history. An absent tag is an empty
// version-1 history; a malformed one is an error that leaves it untouched.
func historyTag(tags map[string]string, wanted string) (key, raw string, history IPHistory, err error) {
	history.Version = 1
	key, raw, found, err := lookupTag(tags, wanted)
	if err != nil || !found {
		return key, raw, history, err
	}
	if len(raw) > maxTagValue {
		return key, raw, history, errors.New("history tag exceeds 256 bytes")
	}
	history = IPHistory{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&history); err != nil {
		return
	}
	var extra any
	if e := decoder.Decode(&extra); e != io.EOF {
		return key, raw, history, errors.New("history tag must contain exactly one JSON object")
	}
	if history.Version != 1 || len(history.IPs) == 0 || len(history.IPs) > 10 {
		return key, raw, history, errors.New("unsupported history schema or IP count; existing tag left untouched")
	}
	seen := map[string]bool{}
	for _, ip := range history.IPs {
		normalized, e := config.PublicIPv4(ip)
		if e != nil || normalized != ip || seen[ip] {
			return key, raw, history, errors.New("history must contain unique canonical public IPv4 addresses")
		}
		seen[ip] = true
	}
	return
}

// targetPolicyFingerprint identifies the policy a target receipt was verified
// under: the target and its action's devices or shared-history settings.
func targetPolicyFingerprint(t config.Target, a config.ActionConfig) string {
	if a.Devices != nil {
		return config.Fingerprint(struct {
			Target  config.Target
			Devices *config.DevicesConfig
		}{t, a.Devices})
	}
	if a.SharedIPHistory == nil {
		return config.Fingerprint(t)
	}
	return config.Fingerprint(struct {
		Target config.Target
		Shared *config.SharedIPHistoryConfig
	}{t, a.SharedIPHistory})
}

// readSharedNSG reads t's NSG, its tags and rules, and checks that Azure
// returned that NSG.
func (e *Engine) readSharedNSG(ctx context.Context, a config.ActionConfig, t config.Target) (azureNSG, error) {
	args := []string{"network", "nsg", "show", "--subscription", t.Subscription, "--resource-group", t.ResourceGroup, "--name", t.NSG, "--only-show-errors", "--output", "json"}
	data, err := e.az(ctx, a, args)
	var nsg azureNSG
	if err != nil {
		return nsg, err
	}
	if err = json.Unmarshal(data, &nsg); err != nil {
		return nsg, fmt.Errorf("NSG %s: invalid Azure JSON: %w", t.NSG, err)
	}
	if !strings.EqualFold(nsg.ID, config.NSGResourceID(t)) || nsg.Name != t.NSG {
		return nsg, fmt.Errorf("NSG %s: registry NSG identity mismatch", t.NSG)
	}
	return nsg, nil
}

// actionKnownIPs is a shared-history action's own ownership evidence: most
// recent verified observations first, then state receipts and configuration.
// It never learns from the unrelated members of before/after sources or from
// human comments.
func (e *Engine) actionKnownIPs(name string, a config.ActionConfig) ([]string, error) {
	var result []string
	if e.StatePath != "" {
		var err error
		result, err = recentHistoryIPs(store.HistoryPath(e.StatePath), ownershipWindow, func(r store.HistoryRecord, add func(string)) {
			if r.Action == name {
				ownershipIPs(r, add)
			}
		})
		if err != nil {
			return nil, err
		}
	}
	state := e.State.Action(name)
	for _, t := range a.Targets {
		receipt := state.Target(t.ID)
		result = append(result, receipt.AppliedIP, receipt.PendingIP, t.BootstrapIP)
		result = append(result, t.KnownIPs...)
	}
	result = append(result, e.Config.KnownIPs...)
	return uniqueIPs(result), nil
}

// historyPlan plans the shared-history tag on nsg for desired. learned is
// known plus the tag's cached history. The planned history (after) is
// desired, every learned address a managed rule of nsg still holds (these
// must fit the limit), then the cached and learned addresses, cut to the
// limit. key is the tag's stored spelling and before its current value.
func historyPlan(nsg azureNSG, a config.ActionConfig, desired string, known []string) (key, before, after string, learned []string, err error) {
	key, before, cached, err := historyTag(nsg.Tags, a.SharedIPHistory.Tag)
	if err != nil {
		return key, before, "", nil, err
	}
	if before == "" && len(nsg.Tags) >= maxNSGTags {
		return key, before, "", nil, fmt.Errorf("NSG already has %d tags; refusing to replace another tag", maxNSGTags)
	}
	learned = uniqueIPs(append(append([]string{}, known...), cached.IPs...))
	owned := map[string]bool{}
	for _, ip := range learned {
		owned[ip] = true
	}
	managed := map[string]bool{}
	for _, t := range a.Targets {
		if t.Kind == config.KindNSG {
			managed[strings.ToLower(expectedResourceID(t))] = true
		}
	}
	pinned := []string{desired}
	for _, r := range nsg.Rules {
		if !managed[strings.ToLower(r.ID)] {
			continue
		}
		for _, source := range r.sourceList() {
			if ip, e := singleIP(source); e == nil && owned[ip] {
				pinned = append(pinned, ip)
			}
		}
	}
	pinned = uniqueIPs(pinned)
	if len(pinned) > a.SharedIPHistory.Limit {
		return key, before, "", learned, errors.New("too many known IPs still referenced by managed rules for this history limit; inspect before trimming")
	}
	ips := uniqueIPs(append(append(pinned, cached.IPs...), learned...))
	if len(ips) > a.SharedIPHistory.Limit {
		ips = ips[:a.SharedIPHistory.Limit]
	}
	data, err := json.Marshal(IPHistory{Version: 1, IPs: ips})
	if err != nil {
		return key, before, "", learned, err
	}
	if len(data) > maxTagValue {
		return key, before, "", learned, errors.New("history JSON exceeds Azure tag size")
	}
	return key, before, string(data), learned, nil
}

// sharedState returns the durable slot for one registry write, creating it.
// Keys are resource IDs (plus "#" and a tag key for tag writes), lowercased.
func (e *Engine) sharedState(name, id string) *store.SharedHistoryState {
	a := e.State.Action(name)
	if a.SharedHistory == nil {
		a.SharedHistory = map[string]*store.SharedHistoryState{}
	}
	key := strings.ToLower(id)
	if a.SharedHistory[key] == nil {
		a.SharedHistory[key] = &store.SharedHistoryState{}
	}
	return a.SharedHistory[key]
}

// pendingWrite returns the unresolved intent in a slot without creating the
// slot, so a read-only check leaves state untouched.
func (e *Engine) pendingWrite(name, id string) *store.HistoryRecord {
	if a := e.State.Actions[name]; a != nil {
		if s := a.SharedHistory[strings.ToLower(id)]; s != nil {
			return s.Pending
		}
	}
	return nil
}

// ensureSharedHistory brings the shared-history tag on group's NSG to the
// plan made from a fresh read (see historyPlan): a changed tag is written and
// verified under a durable intent, and a pending intent that the tag already
// satisfies is settled. It returns the addresses the plan learned.
func (e *Engine) ensureSharedHistory(ctx context.Context, name string, a config.ActionConfig, group config.Target, desired string, known []string) ([]string, error) {
	nsg, err := e.readSharedNSG(ctx, a, group)
	if err != nil {
		return nil, err
	}
	key, before, after, learned, err := historyPlan(nsg, a, desired, known)
	if err != nil {
		return nil, fmt.Errorf("%s history: %w", group.NSG, err)
	}
	state := e.sharedState(name, nsg.ID)
	switch {
	case before != after:
		if !e.Apply {
			e.Log.Log("would_update_shared_history", map[string]any{"nsg": group.NSG, "tag": key, "before": before, "after": after})
			return learned, nil
		}
		if err = e.writeSharedHistory(ctx, name, a, group, nsg, state, desired, key, before, after); err != nil {
			return learned, err
		}
	case state.Pending != nil:
		rec := *state.Pending
		if rec.AfterValue == after {
			rec.Status = statusMetadataReconciled
		} else {
			rec.Status = statusMetadataSuperseded
		}
		if err = e.record(rec); err != nil {
			return learned, err
		}
	}
	state.Value, state.Pending, state.VerifiedAt = after, nil, e.now()
	return learned, e.save()
}

// writeSharedHistory changes tag key on nsg, as read, from before to after.
// It saves the intent first, keeping the operation ID of a pending intent
// for the same change and recording any other superseded, then sends the
// change and verifies it (see sendSharedHistory). A failure is recorded.
func (e *Engine) writeSharedHistory(ctx context.Context, name string, a config.ActionConfig, group config.Target, nsg azureNSG, state *store.SharedHistoryState, desired, key, before, after string) error {
	rec := store.HistoryRecord{Status: statusMetadataIntent, Action: name, Target: "nsg-" + config.Fingerprint(strings.ToLower(nsg.ID))[:16], ResourceID: nsg.ID, IP: desired, Tag: key, BeforeValue: before, AfterValue: after}
	if state.Pending != nil && state.Pending.AfterValue == after && state.Pending.BeforeValue == before {
		rec.OperationID = state.Pending.OperationID
	} else {
		rec.OperationID = store.OperationID()
		if state.Pending != nil {
			previous := *state.Pending
			previous.Status = statusMetadataSuperseded
			if err := e.record(previous); err != nil {
				return err
			}
		}
	}
	rec.At = e.now()
	state.Pending = &rec
	if err := e.save(); err != nil {
		return fmt.Errorf("cannot persist shared-history intent: %w", err)
	}
	if err := e.record(rec); err != nil {
		return err
	}
	if err := e.sendSharedHistory(ctx, a, group, nsg, key, after); err != nil {
		rec.Status, rec.Error = statusMetadataFailed, err.Error()
		if journalErr := e.record(rec); journalErr != nil {
			return errors.Join(err, journalErr)
		}
		return err
	}
	rec.Status = statusMetadataVerified
	if err := e.record(rec); err != nil {
		return err
	}
	e.Log.Log("shared_history_updated", map[string]any{"nsg": group.NSG, "tag": key})
	return nil
}

// sendSharedHistory merges key=after into the tags of nsg, as read, and
// verifies by a fresh read that the tag holds after and that no unrelated
// tag changed meanwhile.
func (e *Engine) sendSharedHistory(ctx context.Context, a config.ActionConfig, group config.Target, nsg azureNSG, key, after string) error {
	args := []string{"tag", "update", "--subscription", group.Subscription, "--resource-id", nsg.ID, "--operation", "Merge", "--tags", key + "=" + after, "--only-show-errors", "--output", "json"}
	if _, err := e.az(ctx, a, args); err != nil {
		return err
	}
	updated, err := e.readSharedNSG(ctx, a, group)
	if err != nil {
		return err
	}
	_, actual, _, err := historyTag(updated.Tags, key)
	if err != nil {
		return err
	}
	if actual != after {
		return errors.New("shared-history tag changed during update; retry with a fresh merged history")
	}
	for other, value := range nsg.Tags {
		if !strings.EqualFold(other, key) && updated.Tags[other] != value {
			return errors.New("an unrelated NSG tag changed during update; inspect before retrying")
		}
	}
	return nil
}

// prepareSharedHistory validates every shared-history registry of a, then
// brings each up to date for desired, before any rule changes. It returns
// the owned addresses learned from local evidence and the registries, and
// the registry NSG targets.
func (e *Engine) prepareSharedHistory(ctx context.Context, name string, a config.ActionConfig, desired string) ([]string, []config.Target, error) {
	if a.SharedIPHistory == nil {
		return nil, nil, nil
	}
	known, err := e.actionKnownIPs(name, a)
	if err != nil {
		return nil, nil, err
	}
	groups := config.NSGGroups(a)
	snapshots := make([]azureNSG, 0, len(groups))
	// Validate every registry before changing any of them or any firewall rule.
	for _, group := range groups {
		nsg, err := e.readSharedNSG(ctx, a, group)
		if err != nil {
			return nil, nil, err
		}
		_, _, cached, err := historyTag(nsg.Tags, a.SharedIPHistory.Tag)
		if err != nil {
			return nil, nil, fmt.Errorf("%s history: %w", group.NSG, err)
		}
		known = uniqueIPs(append(known, cached.IPs...))
		snapshots = append(snapshots, nsg)
	}
	for _, nsg := range snapshots {
		if _, _, _, _, err := historyPlan(nsg, a, desired, known); err != nil {
			return nil, nil, err
		}
	}
	for _, group := range groups {
		learned, err := e.ensureSharedHistory(ctx, name, a, group, desired, known)
		if err != nil {
			return nil, nil, err
		}
		known = uniqueIPs(append(known, learned...))
	}
	return known, groups, nil
}
