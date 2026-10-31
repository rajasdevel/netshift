//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The first signal cancels the context for a graceful stop; a second one must
// end the process at once, as Ctrl-C does for a hung shutdown.
func TestSecondSignalForceQuits(t *testing.T) {
	if os.Getenv("NETSHIFT_SIGNAL_CHILD") == "1" {
		ctx, stop := signalContext(context.Background(), syscall.SIGHUP)
		defer stop()
		_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
		<-ctx.Done()
		for range 250 {
			_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0) // the second signal was swallowed
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSecondSignalForceQuits$")
	cmd.Env = append(os.Environ(), "NETSHIFT_SIGNAL_CHILD=1")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("a second signal did not end the process: %v", err)
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGHUP {
		t.Fatalf("child ended by %v, not SIGHUP", exit)
	}
}
