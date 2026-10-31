package engine

import (
	"context"
	"errors"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

// Open loads the state for once, watch, or run NAME, binds it to the
// profile's identity, and returns the engine. A binding that changed the
// loaded state is marked unsaved, so even a quiet first poll writes it.
func Open(c config.Config, statePath string, apply, verbose bool, log eventlog.Logger) (*Engine, error) {
	state, err := store.Load(statePath)
	if err != nil {
		return nil, err
	}
	saved := config.Fingerprint(state)
	if err = BindIdentity(c, state); err != nil {
		return nil, err
	}
	return &Engine{Config: c, State: state, StatePath: statePath, Apply: apply, Verbose: verbose, Runner: proc.Exec{},
		Observer: discovery.New(c.Monitor), Log: log, savedFingerprint: saved, pendingSave: config.Fingerprint(state) != saved}, nil
}

// Manual runs one named action with a freshly confirmed IP. It leaves the
// observed IP and connectivity to watch, so other actions still receive the
// ip_changed or connectivity_restored events they subscribe to. Stopping it
// (Ctrl-C) leaves the action pending, without a failure or notice.
func (e *Engine) Manual(ctx context.Context, name string) error {
	if e.State.Action(name).Retired {
		return errors.New("identity is retired; use devices activate explicitly")
	}
	o, err := e.confirmCurrentIP(ctx)
	if err != nil {
		return err
	}
	event := store.Event{Type: config.EventManual, IP: o.IP, PreviousIP: e.State.IP, At: e.now()}
	e.queue(name, event)
	if err := e.save(); err != nil {
		return err
	}
	s := e.State.Action(name)
	err = e.executeAction(ctx, name, e.Config.Actions[name], event, true)
	if err != nil && ctx.Err() != nil {
		return errors.Join(ctx.Err(), e.save())
	}
	e.recordOutcome(name, err)
	if err == nil {
		e.completeAction(name, s, event)
	} else {
		s.LastError = err.Error()
	}
	return errors.Join(err, e.flushNotifications(ctx), e.save())
}
