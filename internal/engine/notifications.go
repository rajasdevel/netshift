package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/rajasdevel/netshift/internal/store"
)

// Notice kinds, stored in NotificationState.
const (
	noticeFailure  = "failure"
	noticeRecovery = "recovery"
)

// notifyTimeout bounds one notification helper.
const notifyTimeout = 5 * time.Second

// NotificationCommand returns the native helper that shows a notification on
// platform. title and body are passed as literal arguments, never as script.
func NotificationCommand(platform, title, body string) (string, []string, error) {
	switch platform {
	case "darwin":
		return "/usr/bin/osascript", []string{"-e", "on run argv\n display notification (item 2 of argv) with title (item 1 of argv)\nend run", title, body}, nil
	case "linux":
		return "notify-send", []string{"--app-name=NetShift", "--expire-time=10000", "--", title, body}, nil
	default:
		return "", nil, errors.New("desktop notifications support macOS and Linux only")
	}
}

// recordOutcome updates the named action's notification state after an
// attempt; err is nil on success. It only decides which notice is owed;
// flushNotifications delivers it.
func (e *Engine) recordOutcome(name string, err error) {
	c := e.Config.Notifications
	if !e.Apply || c == nil || !c.Enabled {
		return
	}
	s := e.State.Action(name)
	if s.Retired {
		s.Notice = nil
		return
	}
	if s.Notice == nil {
		if err == nil {
			return
		}
		s.Notice = &store.NotificationState{}
	}
	n := s.Notice
	if err != nil {
		if n.Failures < c.AfterFailures {
			n.Failures++
		}
		if n.Alerted {
			n.Pending = ""
		} else if n.Failures >= c.AfterFailures {
			n.Pending = noticeFailure
		}
	} else {
		n.Failures = 0
		n.Pending = ""
		if n.Alerted {
			n.Pending = noticeRecovery
		}
	}
}

// flushNotifications delivers owed notices outside their cooldown. Each
// attempt is saved before the helper starts, so a crash cannot cause a burst
// of repeats. A failed delivery is logged and retried after the cooldown; it
// never fails the action. Only state-write errors are returned.
func (e *Engine) flushNotifications(ctx context.Context) error {
	c := e.Config.Notifications
	if !e.Apply || c == nil || !c.Enabled || ctx.Err() != nil {
		return nil
	}
	cooldown := time.Duration(c.CooldownSeconds) * time.Second
	for _, name := range e.actionNames() {
		s := e.State.Action(name)
		if s.Retired {
			continue
		}
		n := s.Notice
		if n == nil || n.Pending == "" {
			continue
		}
		// A recovery may follow a failure notice at once; anything else
		// waits out the cooldown since the last attempt.
		cooling := e.now().Before(n.AttemptedAt.Add(cooldown))
		firstRecovery := n.Pending == noticeRecovery && n.AttemptedKind != noticeRecovery
		if cooling && !firstRecovery {
			continue
		}
		kind := n.Pending
		n.AttemptedAt = e.now()
		n.AttemptedKind = kind
		if err := e.save(); err != nil {
			return err
		}
		if err := e.notify(ctx, name, kind); err != nil {
			e.Log.Log("notification_unavailable", map[string]any{"action": name, "error": err.Error()})
		} else {
			n.Alerted = kind == noticeFailure
			n.Pending = ""
			e.Log.Log("notification_sent", map[string]any{"action": name, "kind": kind})
		}
		if err := e.save(); err != nil {
			return err
		}
	}
	return nil
}

// notify shows the notice of kind for the named action, bounded by
// notifyTimeout.
func (e *Engine) notify(ctx context.Context, name, kind string) error {
	title := "NetShift"
	body := fmt.Sprintf("%s: %s failed repeatedly. Inspect this profile with status or doctor for details.", e.Config.Profile, name)
	if kind == noticeRecovery {
		body = fmt.Sprintf("%s: %s recovered.", e.Config.Profile, name)
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	if e.Notify != nil {
		return e.Notify(ctx, title, body)
	}
	program, args, err := NotificationCommand(runtime.GOOS, title, body)
	if err != nil {
		return err
	}
	_, err = e.Runner.Run(ctx, program, args, nil)
	return err
}
