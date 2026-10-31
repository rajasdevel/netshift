package config

import (
	"strings"
)

// NSGResourceID is the Azure resource ID of t's NSG.
func NSGResourceID(t Target) string {
	return "/subscriptions/" + t.Subscription + "/resourceGroups/" + t.ResourceGroup + "/providers/Microsoft.Network/networkSecurityGroups/" + t.NSG
}

// NSGGroups returns the first NSG target of each distinct NSG of a, in
// target order: one target per registry NSG.
func NSGGroups(a ActionConfig) []Target {
	seen := map[string]bool{}
	result := []Target{}
	for _, t := range a.Targets {
		key := strings.ToLower(NSGResourceID(t))
		if t.Kind == KindNSG && !seen[key] {
			seen[key] = true
			result = append(result, t)
		}
	}
	return result
}
