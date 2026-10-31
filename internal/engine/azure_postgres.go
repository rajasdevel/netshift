package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// listDevicePG lists every firewall rule on t's PostgreSQL server. Only a
// successful list can prove a rule absent.
func (e *Engine) listDevicePG(ctx context.Context, a config.ActionConfig, t config.Target) ([]azureRule, error) {
	args := []string{"postgres", "flexible-server", "firewall-rule", "list", "--subscription", t.Subscription, "--resource-group", t.ResourceGroup, "--server-name", t.Server, "--only-show-errors", "--output", "json"}
	raw, err := e.az(ctx, a, args)
	if err != nil {
		return nil, err
	}
	var rules []azureRule
	if err = json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("PostgreSQL server %s: invalid firewall rule list: %w", t.Server, err)
	}
	if rules == nil {
		return nil, fmt.Errorf("PostgreSQL server %s: firewall rule list was not a JSON array", t.Server)
	}
	return rules, nil
}

// findPGRule finds a firewall rule by name, ignoring case like Azure does, so
// a create never overwrites an existing rule.
func findPGRule(rules []azureRule, name string) (azureRule, bool) {
	i := slices.IndexFunc(rules, func(r azureRule) bool { return strings.EqualFold(r.Name, name) })
	if i < 0 {
		return azureRule{}, false
	}
	return rules[i], true
}

// guardDevicePG validates r as t's rule and returns its address, which must
// be one of known.
func guardDevicePG(r azureRule, t config.Target, known []string) (string, error) {
	ip, err := validateRule(r, t)
	if err != nil {
		return "", err
	}
	if !containsIP(known, ip) {
		return "", fmt.Errorf("%s contains IP %s outside this identity's history; refusing ownership", t.Rule, ip)
	}
	return ip, nil
}

// samePGRule reports whether two reads show the same firewall rule.
func samePGRule(a, b azureRule) bool {
	return a.ID == b.ID && a.Name == b.Name && a.StartIP == b.StartIP && a.EndIP == b.EndIP && a.ProvisioningState == b.ProvisioningState
}

// preflightDevicePG checks, before any write, that id's PostgreSQL rules (and
// the legacy owner's configured rule) hold only addresses id owns.
func (e *Engine) preflightDevicePG(ctx context.Context, a config.ActionConfig, id, desired string, known []string) error {
	allowed := append(slices.Clone(known), desired)
	for _, t := range a.Targets {
		if t.Kind != config.KindPostgres {
			continue
		}
		rules, err := e.listDevicePG(ctx, a, t)
		if err != nil {
			return err
		}
		own := devicePGTarget(e.Config, t, id)
		if r, ok := findPGRule(rules, own.Rule); ok {
			if _, err = guardDevicePG(r, own, allowed); err != nil {
				return err
			}
		}
		if id == a.Devices.LegacyIdentity {
			if r, ok := findPGRule(rules, t.Rule); ok {
				if _, err = guardDevicePG(r, t, allowed); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// reconcileDevicePG keeps id's own rule on legacy's server at desired,
// creating it only after this pass's successful list proved it absent, and
// then removes the legacy owner's old configured rule.
func (e *Engine) reconcileDevicePG(ctx context.Context, name string, a config.ActionConfig, legacy config.Target, id, desired string, known []string) error {
	t := devicePGTarget(e.Config, legacy, id)
	rules, err := e.listDevicePG(ctx, a, t)
	if err != nil {
		return err
	}
	allowed := uniqueIPs(append(slices.Clone(known), desired))
	if existing, ok := findPGRule(rules, t.Rule); ok {
		if err = e.updateDevicePG(ctx, name, a, t, existing, desired, allowed); err != nil {
			return err
		}
	} else if err = e.createDevicePG(ctx, name, a, t, id, desired); err != nil {
		return err
	}
	// Only the named legacy owner migrates the two previously configured rules.
	// Its stable replacements have been verified before the old names are removed.
	if id != a.Devices.LegacyIdentity || strings.EqualFold(legacy.Rule, t.Rule) {
		return nil
	}
	if _, ok := findPGRule(rules, legacy.Rule); !ok {
		// The successful list above already proved the old rule absent.
		return e.reconcileDeletedIntent(name, expectedResourceID(legacy), modeWatch)
	}
	return e.deleteDevicePG(ctx, name, a, legacy, id, allowed, modeWatch)
}

// updateDevicePG moves id's existing rule, as listed, to desired.
func (e *Engine) updateDevicePG(ctx context.Context, name string, a config.ActionConfig, t config.Target, listed azureRule, desired string, allowed []string) error {
	ip, err := guardDevicePG(listed, t, allowed)
	if err != nil {
		return err
	}
	s := e.State.Action(name).Target(t.ID)
	if ip == desired && s.PendingChange == nil && s.HistoryInitialized {
		// The list just showed the rule at desired, with no write pending and
		// a baseline already recorded: another read could only repeat that.
		if !e.Apply || e.Verbose {
			e.Log.Log("ip_already_allowed", map[string]any{"target": t.ID, "ip": desired})
		}
	} else if err = e.azureTarget(ctx, name, a, t, s, desired, allowed...); err != nil {
		return err
	}
	return e.deviceTargetReceipt(name, a, t, desired)
}

// createDevicePG creates id's own rule at desired. Create is an upsert in
// Azure; the caller's fresh successful list, never a failed show request, is
// the only evidence of absence.
func (e *Engine) createDevicePG(ctx context.Context, name string, a config.ActionConfig, t config.Target, id, desired string) error {
	if !e.Apply {
		e.Log.Log("would_create_device_postgres_rule", map[string]any{"identity": id, "server": t.Server, "rule": t.Rule, "ip": desired})
		return nil
	}
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusDeviceCreateIntent, Identity: id, Target: t.ID, ResourceID: expectedResourceID(t), IP: desired, AfterSources: []string{desired}})
	if err != nil {
		return err
	}
	args := append(targetArgs(t, "create"), "--start-ip-address", desired, "--end-ip-address", desired)
	if _, err = e.az(ctx, a, args); err != nil {
		return err
	}
	raw, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	_, ip, err := parseRule(raw, t)
	if err != nil {
		return err
	}
	if ip != desired {
		return errors.New("new PostgreSQL rule read-back IP mismatch")
	}
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	if err = e.deviceTargetReceipt(name, a, t, desired); err != nil {
		return err
	}
	e.Log.Log("device_postgres_rule_created", map[string]any{"identity": id, "server": t.Server, "rule": t.Rule})
	return nil
}

// deleteDevicePG deletes t, a rule owned by id, after a successful list and a
// fresh read both show it at an address in known.
func (e *Engine) deleteDevicePG(ctx context.Context, name string, a config.ActionConfig, t config.Target, id string, known []string, mode deviceMode) error {
	rules, err := e.listDevicePG(ctx, a, t)
	if err != nil {
		return err
	}
	r, ok := findPGRule(rules, t.Rule)
	if !ok {
		return e.reconcileDeletedIntent(name, expectedResourceID(t), mode)
	}
	if _, err = guardDevicePG(r, t, known); err != nil {
		return err
	}
	if !e.Apply {
		e.Log.Log("would_delete_device_postgres_rule", map[string]any{"identity": id, "server": t.Server, "rule": t.Rule})
		return nil
	}
	before, err := e.az(ctx, a, targetArgs(t, "show"))
	if err != nil {
		return err
	}
	fresh, err := decodeRule(before)
	if err != nil {
		return err
	}
	if _, err = guardDevicePG(fresh, t, known); err != nil {
		return err
	}
	if !samePGRule(fresh, r) {
		return errors.New("PostgreSQL rule changed during retirement; retry")
	}
	rec, err := e.beginDeviceWrite(name, store.HistoryRecord{Status: statusDeviceDeleteIntent, Identity: id, Target: t.ID, ResourceID: expectedResourceID(t), BeforeSources: []string{r.StartIP}})
	if err != nil {
		return err
	}
	args := append(targetArgs(t, "delete"), "--yes")
	if _, err = e.az(ctx, a, args); err != nil {
		return err
	}
	rules, err = e.listDevicePG(ctx, a, t)
	if err != nil {
		return err
	}
	if _, ok = findPGRule(rules, t.Rule); ok {
		return errors.New("retired PostgreSQL rule still exists")
	}
	if err = e.finishDeviceWrite(name, rec); err != nil {
		return err
	}
	e.Log.Log("device_postgres_rule_deleted", map[string]any{"identity": id, "server": t.Server, "rule": t.Rule})
	return nil
}

// reconcileDeletedIntent settles the pending write of a resource that a
// successful read showed absent. A pending delete succeeded. Under
// retirement, absence also satisfies any other pending write, such as a
// create that failed: there is nothing left to remove. The intent is
// recorded superseded, and a create that lands late keeps its deterministic
// name, so the next cleanup of the retired identity still finds and deletes
// it. Outside retirement, other pending writes need inspection.
func (e *Engine) reconcileDeletedIntent(name, resource string, mode deviceMode) error {
	key := resource + "#"
	pending := e.pendingWrite(name, key)
	if pending == nil {
		return nil
	}
	if pending.Status == statusDeviceDeleteIntent || (pending.Status == statusDeviceIntent && len(pending.AfterSources) == 0) {
		return e.finishDeviceWrite(name, *pending)
	}
	if mode != modeRetire {
		return errors.New("resource missing with an unrelated pending operation; inspect its history")
	}
	return e.supersedeDeviceWrite(name, key, "")
}
