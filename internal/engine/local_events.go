package engine

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/store"
)

// EventEnvironment returns the NETSHIFT_* variables a hook receives for event.
func EventEnvironment(event store.Event) []string {
	// Event holds only strings, a bool, and a current time, which always encode.
	payload, _ := json.Marshal(event)
	return []string{
		"NETSHIFT_EVENT=" + event.Type,
		"NETSHIFT_IP=" + event.IP,
		"NETSHIFT_PREVIOUS_IP=" + event.PreviousIP,
		"NETSHIFT_EVENT_JSON=" + string(payload),
		"NETSHIFT_SOURCE=" + event.Source,
		"NETSHIFT_VALUE=" + event.Value,
		"NETSHIFT_PREVIOUS_VALUE=" + event.PreviousValue,
		"NETSHIFT_TEST=" + strconv.FormatBool(event.Synthetic),
	}
}

// observeLocal emits the opt-in local events before a poll. expected is when
// this poll was due (zero for the first): a poll that starts at least
// ResumeAfterSeconds late means the machine slept, so it emits
// monitor_resumed. With InterfaceChanges it compares the interface snapshot
// with the previous one and emits interface_changed; the first snapshot is
// only a baseline.
//
// It reuses the watch timer: no subscriptions, subprocesses, extra network
// requests, or persisted heartbeat. Disabled sources do no work.
func (e *Engine) observeLocal(expected time.Time) {
	m := e.Config.Monitor
	if m.ResumeAfterSeconds > 0 && !expected.IsZero() {
		// Wall time includes suspend on platforms whose monotonic clock stops asleep.
		late := e.now().Unix() - expected.Unix()
		if late >= int64(m.ResumeAfterSeconds) {
			e.emit(store.Event{Type: config.EventMonitorResumed, IP: e.State.IP, Source: "watch_timer", Value: strconv.FormatInt(late, 10), At: e.now()})
		}
	}
	if !m.InterfaceChanges {
		return
	}
	read := e.Interfaces
	if read == nil {
		read = discovery.InterfaceSnapshot
	}
	value, err := read()
	if err != nil {
		if err.Error() != e.localError {
			e.Log.Log("interface_observation_unavailable", map[string]any{"error": err.Error()})
			e.localError = err.Error()
		}
		return
	}
	if e.localError != "" {
		e.Log.Log("interface_observation_recovered", nil)
		e.localError = ""
	}
	if e.localInitialized && value != e.localBaseline {
		e.emit(store.Event{Type: config.EventInterfaceChanged, IP: e.State.IP, Source: "interfaces", Value: value, PreviousValue: e.localBaseline, At: e.now()})
	}
	e.localBaseline = value
	e.localInitialized = true
}
