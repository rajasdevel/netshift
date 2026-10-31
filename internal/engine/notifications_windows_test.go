//go:build windows

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/proc"
)

// The toast script runs: Windows PowerShell loads the notification types
// and accepts the toast. Whether a banner appears depends on the desktop
// session and its notification settings, which a test cannot see.
func TestToastHelperRuns(t *testing.T) {
	program, args, env, err := NotificationCommand("windows", "NetShift test", `"quoted" & 'single' $(not run) <toast/>`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), notifyTimeout("windows")+10*time.Second)
	defer cancel()
	if out, err := (proc.Exec{}).Run(ctx, program, args, env); err != nil {
		t.Fatalf("toast helper: %v\n%s", err, out)
	}
}
