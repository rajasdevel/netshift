// Package store keeps NetShift's durable records: the state file, its
// single-writer lock, and the append-only history beside it.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
)

// CheckResult is the outcome of one check, shown by status.
type CheckResult struct {
	Name      string    `json:"name"`
	Reachable bool      `json:"reachable"`
	Error     string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

// CheckReceipt records a completed action whose checks have not passed yet,
// so a retry probes again instead of repeating the action.
type CheckReceipt struct {
	ActionCompletedAt time.Time `json:"action_completed_at"`
	Event             Event     `json:"event"`       // event the action completed
	Fingerprint       string    `json:"fingerprint"` // action configuration it completed with
}

// NotificationState is one action's durable notification progress. A failure
// notice is owed after AfterFailures consecutive failures and sent once; the
// next success then owes a recovery notice. Attempts are rate-limited by the
// cooldown, so an unavailable notifier is not spawned on every poll.
type NotificationState struct {
	Failures      int       `json:"failures,omitempty"`       // consecutive failures, capped at AfterFailures
	Alerted       bool      `json:"alerted,omitempty"`        // a failure notice was delivered
	Pending       string    `json:"pending,omitempty"`        // notice owed: noticeFailure, noticeRecovery, or ""
	AttemptedAt   time.Time `json:"attempted_at,omitzero"`    // last delivery attempt
	AttemptedKind string    `json:"attempted_kind,omitempty"` // notice of the last attempt
}

// Event is a confirmed change that actions can subscribe to. Hooks receive it
// as NETSHIFT_* environment variables and as NETSHIFT_EVENT_JSON.
type Event struct {
	Source        string    `json:"source,omitempty"`         // local event origin, such as "interfaces"
	Value         string    `json:"value,omitempty"`          // local event detail
	PreviousValue string    `json:"previous_value,omitempty"` // local event detail before the change
	Synthetic     bool      `json:"synthetic,omitempty"`      // from test-event, not observed
	Type          string    `json:"type"`                     // one of the event* constants
	IP            string    `json:"ip,omitempty"`             // current (or last known) public IPv4
	PreviousIP    string    `json:"previous_ip,omitempty"`    // address before an ip_changed event
	At            time.Time `json:"at"`
}

// TargetState tracks one Azure target's applied and in-flight address.
type TargetState struct {
	HistoryInitialized bool           `json:"history_initialized,omitempty"` // a baseline history record exists
	PendingChange      *HistoryRecord `json:"pending_change,omitempty"`      // intent saved before an Azure write
	AppliedIP          string         `json:"applied_ip,omitempty"`          // address verified in the rule
	PendingIP          string         `json:"pending_ip,omitempty"`          // address being written
	Fingerprint        string         `json:"fingerprint,omitempty"`         // target policy when AppliedIP was verified
	VerifiedAt         time.Time      `json:"verified_at,omitzero"`
}

// SharedHistoryState tracks one NSG's shared IP history tag.
type SharedHistoryState struct {
	Pending    *HistoryRecord `json:"pending,omitempty"` // intent saved before a tag write
	Value      string         `json:"value,omitempty"`   // tag value last verified
	VerifiedAt time.Time      `json:"verified_at,omitzero"`
}

// ActionState is the durable progress of one named action: the pending event,
// retry schedule, verification receipt, and per-target ownership records.
type ActionState struct {
	Verification       *CheckReceipt                  `json:"verification,omitempty"`        // action done, checks not yet passed
	LastChecks         []CheckResult                  `json:"last_checks,omitempty"`         // most recent check results
	Notice             *NotificationState             `json:"notice,omitempty"`              // desktop notification progress
	Retired            bool                           `json:"retired,omitempty"`             // this identity was retired; never run
	SharedHistory      map[string]*SharedHistoryState `json:"shared_history,omitempty"`      // by NSG
	Pending            *Event                         `json:"pending,omitempty"`             // event still to process
	PendingFingerprint string                         `json:"pending_fingerprint,omitempty"` // action configuration when queued
	AppliedFingerprint string                         `json:"applied_fingerprint,omitempty"` // action configuration last applied
	AppliedIP          string                         `json:"applied_ip,omitempty"`          // address last applied
	Attempts           int                            `json:"attempts,omitempty"`            // consecutive failures of Pending
	RetryAt            time.Time                      `json:"retry_at,omitzero"`             // earliest next attempt
	LastError          string                         `json:"last_error,omitempty"`
	LastSuccess        time.Time                      `json:"last_success,omitzero"`
	Targets            map[string]*TargetState        `json:"targets,omitempty"` // by target ID
}

// State is the per-profile file that lets a restarted watcher resume exactly
// where it stopped. Only Engine.save writes it.
type State struct {
	Identity             string                  `json:"identity,omitempty"` // user@host bound to this state
	Version              int                     `json:"version"`
	IP                   string                  `json:"ip,omitempty"`                     // confirmed public IPv4
	Connectivity         string                  `json:"connectivity,omitempty"`           // config.ConnectivityOnline or config.ConnectivityOffline
	CandidateIP          string                  `json:"candidate_ip,omitempty"`           // new address awaiting confirmation
	CandidateCount       int                     `json:"candidate_count,omitempty"`        // consecutive polls that saw CandidateIP
	OfflineCount         int                     `json:"offline_count,omitempty"`          // consecutive failed polls
	LastObservationError string                  `json:"last_observation_error,omitempty"` // stable reason of the current failure
	LastEvent            *Event                  `json:"last_event,omitempty"`
	Actions              map[string]*ActionState `json:"actions"`
}

// maxStateBytes bounds a state file. State grows with targets and devices,
// but stays far below this.
const maxStateBytes = 64 << 20

// New returns the state of a profile that has never run.
func New() *State { return &State{Version: 1, Actions: map[string]*ActionState{}} }

// Action returns the state of the named action, creating it if needed.
func (s *State) Action(name string) *ActionState {
	if s.Actions == nil {
		s.Actions = map[string]*ActionState{}
	}
	a := s.Actions[name]
	if a == nil {
		a = &ActionState{}
		s.Actions[name] = a
	}
	if a.Targets == nil {
		a.Targets = map[string]*TargetState{}
	}
	return a
}

// Target returns the state of the target with this ID, creating it if needed.
func (s *ActionState) Target(id string) *TargetState {
	if s.Targets == nil {
		s.Targets = map[string]*TargetState{}
	}
	t := s.Targets[id]
	if t == nil {
		t = &TargetState{}
		s.Targets[id] = t
	}
	return t
}

// Load reads a state file, or returns a fresh state if it does not
// exist. Anything unreadable is an error rather than a reset, so existing
// ownership records are never silently discarded.
func Load(path string) (*State, error) {
	data, err := fsx.ReadFileLimit(path, maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), nil
	}
	if errors.Is(err, fsx.ErrTooLarge) {
		return nil, fmt.Errorf("state is unreadable; preserve it and investigate: %w", err)
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err = json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state is unreadable; preserve it and investigate: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d; refusing to reset existing state", s.Version)
	}
	if s.IP != "" {
		if _, err = config.PublicIPv4(s.IP); err != nil {
			return nil, fmt.Errorf("invalid state IP: %w", err)
		}
	}
	if s.Actions == nil {
		s.Actions = map[string]*ActionState{}
	}
	return &s, nil
}

// Save writes s to path as indented JSON (see fsx.AtomicWrite).
func Save(path string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsx.AtomicWrite(path, append(b, '\n'), 0600)
}

// userStateDir returns the directory for state files: on macOS
// ~/Library/Application Support/NetShift/state, on Windows
// %LOCALAPPDATA%\NetShift\state, elsewhere $XDG_STATE_HOME/netshift or
// ~/.local/state/netshift.
func userStateDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "NetShift", "state"), nil
	case "windows":
		// %LOCALAPPDATA% stays on this machine and, under the user's
		// profile, is readable only by the user, SYSTEM, and administrators.
		d, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "NetShift", "state"), nil
	}
	// The XDG specification says to ignore relative paths.
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "netshift"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".local", "state", "netshift"), nil
}

// DefaultPath returns the default state file of a profile.
func DefaultPath(profile string) (string, error) {
	d, err := userStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, profile+".json"), nil
}
