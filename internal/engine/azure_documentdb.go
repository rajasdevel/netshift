package engine

import (
	"context"
	"encoding/json"
	"errors"
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
	return e.awaitDocumentDB(ctx, a, t, false)
}

// deleteDocumentDBRule deletes t's rule and waits until a complete list no
// longer shows it.
func (e *Engine) deleteDocumentDBRule(ctx context.Context, a config.ActionConfig, t config.Target) error {
	if _, err := e.documentDB(ctx, a, "delete", expectedResourceID(t), ""); err != nil {
		return err
	}
	return e.awaitDocumentDB(ctx, a, t, true)
}

// awaitDocumentDB reads t's rule until Azure finishes the write: until it is
// provisioned, or, when gone is set, until it is absent. The action's
// timeout bounds the wait.
func (e *Engine) awaitDocumentDB(ctx context.Context, a config.ActionConfig, t config.Target, gone bool) error {
	for {
		rules, err := e.listDeviceRules(ctx, a, t)
		if err != nil {
			return err
		}
		r, found := findNamedRule(rules, t.Rule)
		switch {
		case gone && !found:
			return nil
		case !gone && !found:
			return errors.New("DocumentDB rule missing after its write")
		case !gone && r.ProvisioningState == "Succeeded":
			return nil
		case r.ProvisioningState == "Failed" || r.ProvisioningState == "Canceled":
			return fmt.Errorf("DocumentDB rule %s: Azure reports %s", t.Rule, r.ProvisioningState)
		}
		timer := time.NewTimer(documentDBPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("DocumentDB rule %s still %s: %w", t.Rule, r.ProvisioningState, ctx.Err())
		case <-timer.C:
		}
	}
}
