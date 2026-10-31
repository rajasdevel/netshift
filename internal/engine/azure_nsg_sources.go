package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// ruleShape fingerprints a rule's permissions, ports, and destinations, not
// its mutable source list. Azure's array and single-value forms of a field
// fingerprint identically.
func ruleShape(r azureRule) string {
	return config.NSGShape{
		Access: r.Access, Direction: r.Direction, Protocol: r.Protocol, Priority: r.Priority,
		Destinations: r.destinationList(), Ports: r.portList(), SourcePorts: r.sourcePortList(),
		SourceASGs: r.SourceASGs, DestinationASGs: r.DestinationASGs,
	}.Fingerprint()
}

// sourcePlan plans a single-IP or mapped target's change to desired from a
// rule read (data). It returns the rule's current sources (before), the
// planned sources (after), and the owned addresses the change removes. When
// err is nil, before and after are both non-empty, so callers may compare
// them with slices.Equal; equal lists mean the rule already allows desired.
//
// A dedicated rule (empty SourceMode) must hold exactly one address, and that
// address must be desired or one this target owns (see guardOwnedIP); after
// is the desired address. PostgreSQL lists hold bare addresses, NSG lists
// the rule's own notation, and a new NSG address is written "IP/32".
//
// A mapped rule (config.SourceReplaceKnown) must still have its reviewed shape. Its
// owned addresses (target known_ips, the applied and pending addresses, and
// extraKnown) are replaced by one desired entry at the first one's position;
// a desired entry already present keeps its position and notation, and its
// duplicates are dropped; every other entry stays byte-for-byte, in order.
// A rule holding no owned or desired address is refused rather than appended
// to, as is a plan that would leave the rule empty.
func sourcePlan(data []byte, t config.Target, s *store.TargetState, desired string, extraKnown ...string) (before, after, removed []string, err error) {
	if t.SourceMode != config.SourceReplaceKnown {
		r, current, e := parseRule(data, t)
		if e != nil {
			return nil, nil, nil, e
		}
		if e = guardOwnedIP(current, desired, t, s, extraKnown...); e != nil {
			return nil, nil, nil, e
		}
		if t.Kind == config.KindPostgres {
			before = []string{current}
			after = []string{desired}
		} else {
			before = r.sourceList()
			after = before
			if current != desired {
				after = []string{desired + "/32"}
			}
		}
		if current != desired {
			removed = []string{current}
		}
		return before, after, removed, nil
	}
	r, err := decodeRule(data)
	if err != nil {
		return nil, nil, nil, err
	}
	if !strings.EqualFold(r.ID, expectedResourceID(t)) || r.Name != t.Rule {
		return nil, nil, nil, errors.New("mapped rule identity changed")
	}
	if r.ProvisioningState != "" && r.ProvisioningState != "Succeeded" {
		return nil, nil, nil, fmt.Errorf("rule is still provisioning: %s", r.ProvisioningState)
	}
	if !strings.EqualFold(r.Access, "Allow") || !strings.EqualFold(r.Direction, "Inbound") || len(r.SourceASGs) > 0 || len(r.DestinationASGs) > 0 {
		return nil, nil, nil, errors.New("only existing inbound Allow rules with address sources can be mapped")
	}
	if ruleShape(r) != t.RuleShape {
		return nil, nil, nil, errors.New("mapped rule permissions, destinations, or ports changed; refresh/review its mapping")
	}
	before = r.sourceList()
	known := map[string]bool{}
	for _, ip := range append(append(append([]string{}, t.KnownIPs...), s.AppliedIP, s.PendingIP), extraKnown...) {
		if ip != "" {
			known[ip] = true
		}
	}
	// Keep an already present desired address in its original position/notation.
	desiredPresent := false
	for _, source := range before {
		if ip, e := singleIP(source); e == nil && ip == desired {
			desiredPresent = true
		}
	}
	placed := false
	matched := false
	removedSet := map[string]bool{}
	for _, source := range before {
		ip, e := singleIP(source)
		if e == nil && ip == desired {
			if !placed {
				after = append(after, source)
				placed = true
			}
			continue
		}
		if e == nil && known[ip] {
			matched = true
			if !removedSet[ip] {
				removed = append(removed, ip)
				removedSet[ip] = true
			}
			if !desiredPresent && !placed {
				after = append(after, desired+"/32")
				placed = true
			}
			continue
		}
		after = append(after, source) // Preserve every unrelated entry byte-for-byte.
	}
	if !matched && !desiredPresent {
		return nil, nil, nil, errors.New("none of the explicitly known IPs remain in this rule; refusing to append a new source")
	}
	if len(after) == 0 {
		return nil, nil, nil, errors.New("replacement would empty the rule")
	}
	return before, after, removed, nil
}

// historyMissing reports whether a target of Azure action a has no history
// baseline in s. It only reads s: the quiet poll calls it, and a check must
// neither create state nor make the next checkpoint write it.
func historyMissing(a config.ActionConfig, s *store.ActionState) bool {
	if a.Type != config.ActionAzure {
		return false
	}
	for _, t := range a.Targets {
		if ts := s.Targets[t.ID]; ts == nil || !ts.HistoryInitialized {
			return true
		}
	}
	return false
}
