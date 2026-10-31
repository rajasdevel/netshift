//go:build windows

package engine

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/proc"
)

// The toast script runs: Windows PowerShell loads the notification types
// and accepts the toast. Whether a banner appears depends on the desktop
// session and its notification settings, which a test cannot see.
func TestToastHelperRuns(t *testing.T) {
	program, args, env, err := toastCommand("NetShift test", `"quoted" & 'single' $(not run) <toast/>`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), notifyTimeout+10*time.Second)
	defer cancel()
	if out, err := (proc.Exec{}).Run(ctx, program, args, env); err != nil {
		t.Fatalf("toast helper: %v\n%s", err, out)
	}
}

// The text is only environment data for a constant script.
func TestToastArgumentsRemainLiteral(t *testing.T) {
	body := "'); Remove-Item C:\\ -Recurse; ('$(whoami)<toast/>"
	program, args, env, err := toastCommand("NetShift", body)
	if err != nil || !filepath.IsAbs(program) || !strings.EqualFold(filepath.Base(program), "powershell.exe") ||
		!slices.Equal(env, []string{"NETSHIFT_NOTIFY_TITLE=NetShift", "NETSHIFT_NOTIFY_BODY=" + body}) {
		t.Fatal(program, env, err)
	}
	if i := slices.Index(args, "-EncodedCommand"); i < 0 || i != len(args)-2 || !slices.Contains(args, "-NoProfile") {
		t.Fatalf("arguments: %q", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "Remove-Item") || strings.Contains(arg, "NetShift") {
			t.Fatalf("text reached the command line: %q", arg)
		}
	}
	_, again, _, _ := toastCommand("other", "text")
	if !slices.Equal(args, again) {
		t.Fatal("the script varies with the text")
	}
}
