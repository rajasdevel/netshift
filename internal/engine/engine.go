// Package engine turns observations into events and runs the profile's
// actions for them. It owns the watch loop, retries, post-action checks,
// notifications, and local events, and it implements the built-in Azure
// allowlist action in the azure_*.go files.
//
// The engine saves its intent before an external change and verifies the
// result afterward; see Engine for how it persists progress.
package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

// Engine turns observations into events and runs the actions that subscribe
// to them. One Engine owns one profile's state file.
//
// Persistence rules: every external write is preceded by a saved intent, and
// save is the only path to disk. pendingSave marks in-memory changes that a
// quiet-poll checkpoint must not skip; savedFingerprint is the hash of the
// state last written successfully, so an unchanged poll writes nothing.
type Engine struct {
	Config    config.Config      // validated profile; immutable while watching
	State     *store.State       // durable progress, written only by save
	StatePath string             // state file; the history file lives beside it
	Apply     bool               // run actions and write state and history; false previews
	Verbose   bool               // also log targets that were verified unchanged
	Runner    proc.Runner        // starts hooks, az, and notification helpers
	Observer  discovery.Observer // discovers the public IPv4
	Log       eventlog.Logger    // event log; step and watch point an unset Log.Now at the engine clock

	// Test seams; nil selects the real implementation.
	Now        func() time.Time                                // clock (time.Now)
	Save       func(*store.State) error                        // store.Save to StatePath
	History    func(store.HistoryRecord) error                 // store.AppendHistory beside StatePath
	Check      func(context.Context, config.CheckConfig) error // probe
	Notify     func(context.Context, string, string) error     // NotificationCommand via Runner
	Interfaces func() (string, error)                          // discovery.InterfaceSnapshot

	localBaseline    string            // last interface snapshot, for interface_changed
	localInitialized bool              // localBaseline holds a real snapshot
	localError       string            // last interface read error, logged once
	cachedNames      []string          // action names, cached by watch
	cachedActions    map[string]string // action fingerprints by name, cached by watch
	savedFingerprint string            // hash of the state last written successfully
	pendingSave      bool              // in-memory changes a quiet checkpoint must not skip
}

// now returns the engine clock in UTC.
func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// bindLogClock points an unset Log.Now at the engine clock, so log times
// agree with state times and are deterministic under a test clock. It
// allocates once; later calls do nothing.
func (e *Engine) bindLogClock() {
	if e.Log.Now == nil {
		e.Log.Now = e.now
	}
}

// save writes the state when it differs from the last successful write.
// A failed write leaves pendingSave set so the next poll retries it.
// Previews never write.
func (e *Engine) save() error {
	if !e.Apply {
		return nil
	}
	// Always check explicit saves: cloud intents and receipts rely on this path.
	// A failed save must be retried even if the next observation is unchanged.
	e.pendingSave = true
	hash := config.Fingerprint(e.State)
	if hash == e.savedFingerprint {
		e.pendingSave = false
		return nil
	}
	var err error
	if e.Save != nil {
		err = e.Save(e.State)
	} else {
		err = store.Save(e.StatePath, e.State)
	}
	if err == nil {
		e.savedFingerprint = hash
		e.pendingSave = false
	}
	return err
}

// queue makes event the pending event of the named action. A newer event
// replaces an older one, so delivery coalesces to the latest network state.
// Queuing restarts the retry schedule, drops any check receipt, and records
// the action configuration the plan was made for. A retired action ignores
// events.
func (e *Engine) queue(name string, event store.Event) {
	s := e.State.Action(name)
	if s.Retired {
		return
	}
	e.pendingSave = true
	s.Verification = nil
	s.Pending = &event
	s.PendingFingerprint = e.actionFingerprint(name)
	s.Attempts = 0
	s.RetryAt = time.Time{}
	s.LastError = ""
}

// emit records a confirmed event as the last event, logs it, and queues it
// for every subscribed action. The event is persisted even when no action
// subscribes to it.
func (e *Engine) emit(event store.Event) {
	e.pendingSave = true
	e.State.LastEvent = &event
	e.Log.Log(event.Type, map[string]any{"ip": event.IP, "previous_ip": event.PreviousIP, "source": event.Source, "value": event.Value})
	for _, name := range e.actionNames() {
		if config.Listens(e.Config.Actions[name], event.Type) {
			e.queue(name, event)
		}
	}
}

// addressAcceptance says when step accepts a verified new address.
type addressAcceptance bool

const (
	acceptConfirmed addressAcceptance = false // after Monitor.Confirmations consecutive polls (watch)
	acceptAtOnce    addressAcceptance = true  // on the first verified observation (once)
)

// reapplyScope says which Azure actions step re-applies.
type reapplyScope bool

const (
	reapplyStale reapplyScope = false // those needsReconcile finds out of date (watch)
	reapplyAll   reapplyScope = true  // every Azure action and target (once)
)

// step processes one observation in three phases. observe updates the
// observed state and emits the events it confirms; plan queues Azure
// reconciliation and replans stale pending events; run executes the actions
// that are due and sends notifications. A checkpoint between plan and run
// makes queued work durable before any of it starts.
//
// accept and reapply are acceptConfirmed and reapplyStale for watch, and
// acceptAtOnce and reapplyAll for the once command. A quiet poll, where
// nothing changes, allocates nothing and writes nothing.
func (e *Engine) step(ctx context.Context, o discovery.Observation, accept addressAcceptance, reapply reapplyScope) error {
	e.bindLogClock()
	before := observationState(e.State)
	now := e.now()
	e.observe(o, accept, now)
	s := e.State
	ready := o.Online && o.Verified && o.IP == s.IP && s.IP != ""
	force := reapply == reapplyAll
	e.plan(ready, force, now)
	// Only this poll checkpoint can be skipped. Observation changes, queued/local
	// events, new action state, and failed saves still reach the full save path.
	if before != observationState(s) || e.pendingSave || e.savedFingerprint == "" {
		if err := e.save(); err != nil {
			return err
		}
	}
	return e.run(ctx, ready, force, now)
}

// observe records the observation error, if any, and advances the outage and
// address confirmation counters, emitting connectivity_lost,
// connectivity_restored, and ip_changed when they confirm a change.
func (e *Engine) observe(o discovery.Observation, accept addressAcceptance, now time.Time) {
	s := e.State
	switch {
	case o.Err != nil:
		reason := o.Reason
		if reason == "" {
			reason = o.Err.Error()
		}
		// Log an outage once per distinct reason, not on every poll.
		if s.LastObservationError != reason {
			e.Log.Log("observation_unavailable", map[string]any{"error": o.Err.Error()})
			s.LastObservationError = reason
		}
	case s.LastObservationError != "":
		e.Log.Log("observation_recovered", nil)
		s.LastObservationError = ""
	}
	if !o.Online {
		s.CandidateIP, s.CandidateCount = "", 0
		if s.OfflineCount < e.Config.Monitor.OfflineConfirmations {
			s.OfflineCount++
		}
		if s.OfflineCount >= e.Config.Monitor.OfflineConfirmations && s.Connectivity != config.ConnectivityOffline {
			s.Connectivity = config.ConnectivityOffline
			e.emit(store.Event{Type: config.EventConnectivityLost, IP: s.IP, At: now})
		}
		return
	}
	s.OfflineCount = 0
	wasOffline := s.Connectivity == config.ConnectivityOffline
	s.Connectivity = config.ConnectivityOnline
	e.confirmIP(o, accept, now)
	if wasOffline {
		e.emit(store.Event{Type: config.EventConnectivityRestored, IP: s.IP, At: now})
	}
}

// confirmIP counts consecutive verified observations of a new address and
// emits ip_changed once Monitor.Confirmations agree, or at once with
// acceptAtOnce. Any other observation clears the candidate.
func (e *Engine) confirmIP(o discovery.Observation, accept addressAcceptance, now time.Time) {
	s := e.State
	if !o.Verified || o.IP == s.IP {
		s.CandidateIP, s.CandidateCount = "", 0
		return
	}
	if s.CandidateIP == o.IP {
		s.CandidateCount++
	} else {
		s.CandidateIP, s.CandidateCount = o.IP, 1
	}
	if accept == acceptAtOnce || s.CandidateCount >= e.Config.Monitor.Confirmations {
		previous := s.IP
		s.IP = o.IP
		s.CandidateIP, s.CandidateCount = "", 0
		e.emit(store.Event{Type: config.EventIPChanged, IP: s.IP, PreviousIP: previous, At: now})
	}
}

// plan queues the work the current address calls for. Until the address is
// ready (confirmed by this observation) it only creates missing action state.
// Then it queues a reconcile event where needsReconcile says so, and requeues
// a pending event whose action configuration changed after it was queued.
func (e *Engine) plan(ready, force bool, now time.Time) {
	s := e.State
	for _, name := range e.actionNames() {
		if s.Actions[name] == nil {
			e.pendingSave = true // new action state must reach disk
		}
		as := s.Action(name)
		if !ready || as.Retired {
			continue
		}
		a := e.Config.Actions[name]
		if e.needsReconcile(name, &a, as, s.IP, now, force) {
			e.queue(name, store.Event{Type: config.EventReconcile, IP: s.IP, At: now})
		}
		// A config edit invalidates a pending plan without losing target receipts.
		if as.Pending != nil && as.PendingFingerprint != e.actionFingerprint(name) {
			event := *as.Pending
			event.IP = s.IP
			event.At = now
			e.queue(name, event)
		}
	}
}

// needsReconcile reports whether the action name, with configuration a and
// state as, must be queued as a reconcile event for the confirmed address ip,
// so that its Azure rules are read back and repaired. It must when:
//
//   - force is set (the once command);
//   - a pending event is for an older address, so its plan is stale;
//
// or, when nothing is pending:
//
//   - a device registry's ReconcileSeconds passed since the last success; or
//   - the action configuration, the applied address, or a target's history
//     baseline differs from what was last applied.
//
// A pending event for ip is already the work to do. Command actions are
// never reconciled.
func (e *Engine) needsReconcile(name string, a *config.ActionConfig, as *store.ActionState, ip string, now time.Time, force bool) bool {
	switch {
	case a.Type != config.ActionAzure:
		return false
	case force:
		return true
	case as.Pending != nil:
		return as.Pending.IP != ip
	case a.Devices != nil && now.Sub(as.LastSuccess) >= time.Duration(a.Devices.ReconcileSeconds)*time.Second:
		return true
	default:
		return as.AppliedFingerprint != e.actionFingerprint(name) || as.AppliedIP != ip || historyMissing(*a, as)
	}
}

// run executes every action whose pending event is due, saving each outcome
// before the next action starts, then sends due notifications. Azure actions
// also wait until their pending address is the ready, current one. Stopping
// (ctx canceled) mid-action leaves it pending, without backoff or a failure
// notice, for the next start.
func (e *Engine) run(ctx context.Context, ready, force bool, now time.Time) error {
	var failures []error
	for _, name := range e.actionNames() {
		as := e.State.Action(name)
		if as.Retired || as.Pending == nil || now.Before(as.RetryAt) {
			continue
		}
		a := e.Config.Actions[name]
		if a.Type == config.ActionAzure && (!ready || as.Pending.IP != e.State.IP) {
			continue
		}
		event := *as.Pending
		e.Log.Log("action_started", map[string]any{"action": name, "trigger": event.Type, "apply": e.Apply})
		// The first attempt after an outage re-applies every target rather
		// than trusting receipts from before it.
		forceTargets := force || (event.Type == config.EventConnectivityRestored && as.Attempts == 0)
		err := e.executeAction(ctx, name, a, event, forceTargets)
		if err != nil && ctx.Err() != nil {
			return errors.Join(ctx.Err(), e.save())
		}
		e.recordOutcome(name, err)
		if err == nil {
			e.completeAction(name, as, event)
		} else {
			e.scheduleRetry(name, as, err)
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
		if saveErr := e.save(); saveErr != nil {
			return saveErr
		}
	}
	if err := e.flushNotifications(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// completeAction records that the named action handled event.
func (e *Engine) completeAction(name string, as *store.ActionState, event store.Event) {
	as.Pending = nil
	as.Attempts = 0
	as.RetryAt = time.Time{}
	as.LastError = ""
	as.LastSuccess = e.now()
	as.AppliedFingerprint = e.actionFingerprint(name)
	as.AppliedIP = event.IP
	e.Log.Log("action_completed", map[string]any{"action": name, "apply": e.Apply})
}

// scheduleRetry records a failed attempt and when the next one is due.
func (e *Engine) scheduleRetry(name string, as *store.ActionState, err error) {
	as.Attempts++
	as.RetryAt = e.now().Add(retryDelay(e.Config.Monitor, as.Attempts))
	as.LastError = err.Error()
	e.Log.Log("action_retry_scheduled", map[string]any{"action": name, "error": err.Error(), "retry_at": as.RetryAt})
}

// retryDelay is the wait after the given number of consecutive failures:
// RetrySeconds after the first, doubling with each further failure, and never
// more than MaxRetrySeconds.
func retryDelay(m config.MonitorConfig, failures int) time.Duration {
	delay := time.Duration(m.RetrySeconds) * time.Second
	maxDelay := time.Duration(m.MaxRetrySeconds) * time.Second
	for n := 1; n < failures && delay < maxDelay; n++ {
		delay *= 2
	}
	return min(delay, maxDelay)
}

// pollSnapshot holds the state fields a poll can change. Comparing two
// snapshots is allocation-free. Action/event mutations use pendingSave or an
// explicit save; this is not a replacement for durable-intent checks.
type pollSnapshot struct {
	IP, Connectivity, CandidateIP, Error string
	CandidateCount, OfflineCount         int
}

// observationState takes the poll snapshot of s.
func observationState(s *store.State) pollSnapshot {
	return pollSnapshot{s.IP, s.Connectivity, s.CandidateIP, s.LastObservationError, s.CandidateCount, s.OfflineCount}
}

// Once serves the once command: it confirms the current address across
// sources in one invocation and processes it as one step, accepting a new
// address at once and re-applying every Azure action.
func (e *Engine) Once(ctx context.Context) error {
	o, err := e.confirmCurrentIP(ctx)
	if err != nil {
		return err
	}
	return e.step(ctx, o, acceptAtOnce, reapplyAll)
}

// confirmCurrentIP asks the discovery sources for the current address without
// a known stable IP, so a new address needs two agreeing sources.
func (e *Engine) confirmCurrentIP(ctx context.Context) (discovery.Observation, error) {
	o := e.Observer.Observe(ctx, "")
	if o.Verified {
		return o, nil
	}
	err := o.Err
	if err == nil {
		err = errors.New("no verified answer")
	}
	return o, fmt.Errorf("cannot confirm current IP: %w", err)
}

// Watch serves the watch command: it polls until ctx is canceled. Each cycle
// observes local events and the public address, then steps. The next cycle
// starts a full interval after this one's work ends, so slow observations or
// actions never cause catch-up polls. Action failures are persisted with
// retry deadlines and logged; a failed state write ends watch with an error
// so the service manager restarts it safely.
func (e *Engine) Watch(ctx context.Context) error {
	e.bindLogClock()
	e.cacheActions()
	var expected time.Time
	delay := time.Duration(e.Config.Monitor.IntervalSeconds) * time.Second
	timer := time.NewTimer(delay)
	defer timer.Stop()
	e.Log.Log("monitor_started", map[string]any{"profile": e.Config.Profile, "apply": e.Apply, "interval_seconds": e.Config.Monitor.IntervalSeconds})
	for {
		e.observeLocal(expected)
		o := e.Observer.Observe(ctx, e.State.IP)
		if ctx.Err() != nil {
			return e.stopWatch()
		}
		if err := e.step(ctx, o, acceptConfirmed, reapplyStale); err != nil {
			if ctx.Err() != nil {
				// A stop request interrupted an action, which stays pending
				// for the next start; that is not an incomplete cycle.
				return e.stopWatch()
			}
			// Action failures are persisted with retry deadlines; a state-write failure
			// must stop the writer so the service manager can restart it safely.
			if saveErr := e.save(); saveErr != nil {
				return saveErr
			}
			e.Log.Log("cycle_incomplete", map[string]any{"error": err.Error()})
		}
		expected = e.now().Add(delay)
		// Since Go 1.23, Reset cannot deliver a stale tick, even if startup
		// work outlasted the first timer. Always wait fully after work.
		timer.Reset(delay)
		select {
		case <-ctx.Done():
			return e.stopWatch()
		case <-timer.C:
		}
	}
}

// stopWatch ends watch after a stop request. It saves what changed since the
// last checkpoint, such as a local event queued before the request, and logs
// monitor_stopped, with the error if that save failed.
func (e *Engine) stopWatch() error {
	err := e.save()
	var fields map[string]any
	if err != nil {
		fields = map[string]any{"error": err.Error()}
	}
	e.Log.Log("monitor_stopped", fields)
	return err
}

// cacheActions caches action names and fingerprints for watch, whose profile
// is immutable until restart. Only watch caches: CLI operations and tests
// that replace a profile must not observe stale plans.
func (e *Engine) cacheActions() {
	e.cachedNames = config.ActionNames(e.Config)
	e.cachedActions = make(map[string]string, len(e.cachedNames))
	for _, name := range e.cachedNames {
		e.cachedActions[name] = config.Fingerprint(e.Config.Actions[name])
	}
}

// actionNames returns the action names in run order, cached while watching.
func (e *Engine) actionNames() []string {
	if e.cachedNames != nil {
		return e.cachedNames
	}
	return config.ActionNames(e.Config)
}

// actionFingerprint returns the fingerprint of the named action's
// configuration, cached while watching.
func (e *Engine) actionFingerprint(name string) string {
	if v, ok := e.cachedActions[name]; ok {
		return v
	}
	return config.Fingerprint(e.Config.Actions[name])
}
