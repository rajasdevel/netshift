//go:build windows

package cli

import "testing"

// Only the scheduled task passes --scheduled-task, which lets watch close
// its console; any other run keeps it.
func TestScheduledTaskMarker(t *testing.T) {
	captureOutput(t)
	t.Cleanup(func() { startedByTask = false })
	if err := cli(t.Context(), []string{"--scheduled-task", "version"}); err != nil || !startedByTask {
		t.Fatalf("marker: %v %t", err, startedByTask)
	}
	if err := cli(t.Context(), []string{"version"}); err != nil || startedByTask {
		t.Fatalf("without the marker: %v %t", err, startedByTask)
	}
	releaseOwnConsole() // without the marker, a no-op that keeps this test's console
}
