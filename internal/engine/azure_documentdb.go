package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
)

// The core Azure CLI has no command for DocumentDB firewall rules (only
// preview extensions do), so NetShift sends the Azure Resource Manager
// requests itself with az rest, which accepts a resource ID as the URL.
const documentDBAPI = "?api-version=2025-09-01"

// documentDBPoll is how often a DocumentDB write is checked: az rest does
// not wait for Azure's long-running operations.
var documentDBPoll = 3 * time.Second

// documentDB sends one request for the resource id.
func (e *Engine) documentDB(ctx context.Context, a config.ActionConfig, method, id, body string) ([]byte, error) {
	args := []string{"rest", "--method", method, "--url", id + documentDBAPI, "--only-show-errors", "--output", "json"}
	if body != "" {
		args = append(args, "--body", body)
	}
	return e.az(ctx, a, args)
}

// listDocumentDBRules returns the JSON array of every firewall rule on t's
// cluster. A paged list is refused: only a complete list proves a rule absent.
func (e *Engine) listDocumentDBRules(ctx context.Context, a config.ActionConfig, t config.Target) ([]byte, error) {
	cluster := strings.TrimSuffix(expectedResourceID(t), "/"+t.Rule)
	raw, err := e.documentDB(ctx, a, "get", cluster, "")
	if err != nil {
		return nil, err
	}
	var page struct {
		Value    json.RawMessage `json:"value"`
		NextLink string          `json:"nextLink"`
	}
	if err = json.Unmarshal(raw, &page); err != nil {
		return nil, fmt.Errorf("%s: invalid firewall rule list: %w", ruleHost(t), err)
	}
	if page.NextLink != "" {
		return nil, fmt.Errorf("%s: the firewall rule list has more than one page, which NetShift does not read", ruleHost(t))
	}
	return page.Value, nil
}

// putDocumentDBRule sets t's rule to allow ip alone, creating it if needed,
// and waits until Azure has applied it.
func (e *Engine) putDocumentDBRule(ctx context.Context, a config.ActionConfig, t config.Target, ip string) error {
	body := `{"properties":{"startIpAddress":"` + ip + `","endIpAddress":"` + ip + `"}}`
	if _, err := e.documentDB(ctx, a, "put", expectedResourceID(t), body); err != nil {
		return err
	}
	return e.awaitDocumentDB(ctx, a, t, ip)
}

// deleteDocumentDBRule deletes t's rule and waits until a complete list no
// longer shows it.
func (e *Engine) deleteDocumentDBRule(ctx context.Context, a config.ActionConfig, t config.Target) error {
	if _, err := e.documentDB(ctx, a, "delete", expectedResourceID(t), ""); err != nil {
		return err
	}
	return e.awaitDocumentDB(ctx, a, t, "")
}

// awaitDocumentDB reads t's rule list until Azure finishes the write: until
// the rule is provisioned at ip, or, when ip is empty, until it is absent.
// The list is eventually consistent: for a few seconds after a write it can
// omit a new rule or show an earlier version, so neither ends the wait. A
// read of the rule itself, which Azure answers consistently, confirms an
// absence or a failure before the wait ends on it. The action's timeout
// bounds the wait.
func (e *Engine) awaitDocumentDB(ctx context.Context, a config.ActionConfig, t config.Target, ip string) error {
	state := "not listed"
	for {
		done, next, err := e.documentDBSettled(ctx, a, t, ip)
		if done || err != nil && ctx.Err() == nil {
			return err
		}
		if err != nil {
			return fmt.Errorf("DocumentDB rule %s still %s: %w", t.Rule, state, err)
		}
		state = next
		timer := time.NewTimer(documentDBPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("DocumentDB rule %s still %s: %w", t.Rule, state, ctx.Err())
		case <-timer.C:
		}
	}
}

// documentDBSettled reads t's rule once for awaitDocumentDB. It reports
// whether the write to ip (or the delete, when ip is empty) is done, and
// otherwise the rule's state for a timeout message.
func (e *Engine) documentDBSettled(ctx context.Context, a config.ActionConfig, t config.Target, ip string) (bool, string, error) {
	rules, err := e.listDeviceRules(ctx, a, t)
	if err != nil {
		return false, "", err
	}
	r, found := findNamedRule(rules, t.Rule)
	failed := r.ProvisioningState == "Failed" || r.ProvisioningState == "Canceled"
	if ip != "" {
		switch {
		case !found:
			return false, "not listed", nil
		case r.StartIP != ip || r.EndIP != ip:
			return false, "listed at " + r.StartIP, nil
		case r.ProvisioningState == "Succeeded":
			return true, "", nil
		case failed:
			return false, "", fmt.Errorf("DocumentDB rule %s: Azure reports %s", t.Rule, r.ProvisioningState)
		}
		return false, r.ProvisioningState, nil
	}
	if found && !failed {
		return false, r.ProvisioningState, nil
	}
	// The list omits the rule or shows it failed, perhaps from an earlier
	// write: ask Azure for the rule itself.
	gone, got, err := e.documentDBRuleGone(ctx, a, t)
	switch {
	case err != nil:
		return false, "", err
	case gone && !found:
		return true, "", nil
	case gone:
		return false, "listed after its deletion", nil
	case got.ProvisioningState == "Failed" || got.ProvisioningState == "Canceled":
		return false, "", fmt.Errorf("DocumentDB rule %s: Azure reports %s", t.Rule, got.ProvisioningState)
	}
	return false, got.ProvisioningState, nil
}

// documentDBRuleGone reads t's rule and reports whether Azure answered that
// it does not exist; only that answer counts as absence. Otherwise it
// returns the rule.
func (e *Engine) documentDBRuleGone(ctx context.Context, a config.ActionConfig, t config.Target) (bool, azureRule, error) {
	raw, err := e.showRule(ctx, a, t)
	if err != nil {
		if strings.Contains(err.Error(), documentDBNotFound) {
			return true, azureRule{}, nil
		}
		return false, azureRule{}, err
	}
	r, err := decodeRule(raw)
	return false, r, err
}

// documentDBNotFound begins az rest's error for a firewall rule that does not
// exist, as Azure sent it for API version 2025-09-01.
const documentDBNotFound = `Not Found({"error":{"code":"not_found"`
