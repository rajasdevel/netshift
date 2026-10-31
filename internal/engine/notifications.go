package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unicode/utf16"

	"github.com/rajasdevel/netshift/internal/store"
)

// Notice kinds, stored in NotificationState.
const (
	noticeFailure  = "failure"
	noticeRecovery = "recovery"
)

// notifyTimeout bounds one notification helper. Windows PowerShell can take
// several seconds to start.
func notifyTimeout(platform string) time.Duration {
	if platform == "windows" {
		return 20 * time.Second
	}
	return 5 * time.Second
}

// toastScript shows a Windows toast with the title and body it reads from
// the environment. It is a constant: the text reaches it only as data, as
// text nodes it never parses, so nothing in it can be read as code or XML.
// Toasts need an app ID that Windows knows; Windows PowerShell's is
// registered on every installation.
const toastScript = `$ErrorActionPreference = 'Stop'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$toast = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$lines = $toast.GetElementsByTagName('text')
$null = $lines.Item(0).AppendChild($toast.CreateTextNode($env:NETSHIFT_NOTIFY_TITLE))
$null = $lines.Item(1).AppendChild($toast.CreateTextNode($env:NETSHIFT_NOTIFY_BODY))
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($toast))
`

// NotificationCommand returns the native helper that shows a notification on
// platform, its arguments, and environment entries it needs. title and body
// are passed as literal arguments (on Windows, environment values), never as
// script.
func NotificationCommand(platform, title, body string) (program string, args, env []string, err error) {
	switch platform {
	case "darwin":
		return "/usr/bin/osascript", []string{"-e", "on run argv\n display notification (item 2 of argv) with title (item 1 of argv)\nend run", title, body}, nil, nil
	case "linux":
		return "notify-send", []string{"--app-name=NetShift", "--expire-time=10000", "--", title, body}, nil, nil
	case "windows":
		// -EncodedCommand takes the script as Base64 UTF-16, so no quoting
		// rules of the command line or of PowerShell apply to it.
		units := utf16.Encode([]rune(toastScript))
		script := make([]byte, 0, 2*len(units))
		for _, u := range units {
			script = append(script, byte(u), byte(u>>8))
		}
		args := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(script)}
		return "powershell.exe", args, []string{"NETSHIFT_NOTIFY_TITLE=" + title, "NETSHIFT_NOTIFY_BODY=" + body}, nil
	default:
		return "", nil, nil, errors.New("desktop notifications support macOS, Linux, and Windows only")
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
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout(runtime.GOOS))
	defer cancel()
	if e.Notify != nil {
		return e.Notify(ctx, title, body)
	}
	program, args, env, err := NotificationCommand(runtime.GOOS, title, body)
	if err != nil {
		return err
	}
	_, err = e.Runner.Run(ctx, program, args, env)
	return err
}
