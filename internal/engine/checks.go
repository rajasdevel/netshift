package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
	"github.com/rajasdevel/netshift/internal/version"
)

// Probe runs one check within its timeout. HTTP checks use a fresh
// connection, honor proxy settings, never follow redirects, and do not read
// the response body.
func Probe(ctx context.Context, c config.CheckConfig) error {
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	if c.Type == config.CheckTCP {
		conn, err := dialer.DialContext(ctx, "tcp", c.Address)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, DisableKeepAlives: true, TLSHandshakeTimeout: timeout, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 16384}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NetShift/"+version.Number)
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	// Status is the contract. Close immediately without reading a response body.
	if response.StatusCode != c.ExpectedStatus {
		return fmt.Errorf("HTTP status %d; expected %d", response.StatusCode, c.ExpectedStatus)
	}
	return nil
}

// checkTargets runs checks in order, stopping early if ctx ends, and returns
// every result with the joined failures.
func (e *Engine) checkTargets(ctx context.Context, checks []config.CheckConfig) ([]store.CheckResult, error) {
	results := make([]store.CheckResult, 0, len(checks))
	var failures []error
	check := e.Check
	if check == nil {
		check = Probe
	}
	for _, c := range checks {
		err := check(ctx, c)
		r := store.CheckResult{Name: c.Name, Reachable: err == nil, At: e.now()}
		if err != nil {
			r.Error = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", c.Name, err))
		}
		results = append(results, r)
		if ctx.Err() != nil {
			break
		}
	}
	return results, errors.Join(failures...)
}

// executeAction runs one attempt of the named action for event, bounded by
// the action timeout, then its checks. Success of the action is persisted as
// a CheckReceipt before verification, so retries and restarts probe again
// without repeating an action that already succeeded. force is passed to the
// Azure action (see runAzure).
func (e *Engine) executeAction(ctx context.Context, name string, a config.ActionConfig, event store.Event, force bool) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSeconds)*time.Second)
	defer cancel()
	s := e.State.Action(name)
	policy := config.Fingerprint(a)
	same := s.Verification != nil && s.Verification.Fingerprint == policy && s.Verification.Event == event
	// Long verification waits must not suppress scheduled device reconciliation
	// or prevent a remote retirement from being observed. Commands never rerun.
	if same && a.Devices != nil && e.now().Sub(s.Verification.ActionCompletedAt) >= time.Duration(a.Devices.ReconcileSeconds)*time.Second {
		same = false
	}
	if !same {
		if err := e.runAction(ctx, name, a, event, force); err != nil {
			return err
		}
		if s.Retired {
			s.Verification = nil
			return nil
		}
		if len(a.Checks) == 0 {
			return nil
		}
		if !e.Apply {
			e.Log.Log("would_check_targets", map[string]any{"action": name, "count": len(a.Checks)})
			return nil
		}
		s.Verification = &store.CheckReceipt{Event: event, Fingerprint: policy, ActionCompletedAt: e.now()}
		if err := e.save(); err != nil {
			return err
		}
	}
	results, err := e.checkTargets(ctx, a.Checks)
	s.LastChecks = results
	if err != nil {
		return fmt.Errorf("post-action verification: %w", err)
	}
	s.Verification = nil
	return nil
}
