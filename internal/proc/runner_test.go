//go:build darwin || linux

package proc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// os/exec copies pipes with io.Copy, so the limit must hold even when the
// destination's Write method is bypassed by a ReadFrom fast path.
func TestRunnerBoundsOutput(t *testing.T) {
	data, err := (Exec{}).Run(t.Context(), "/bin/sh", []string{"-c", "head -c 3000000 /dev/zero"}, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeded the output limit") || data != nil {
		t.Fatalf("len=%d err=%v", len(data), err)
	}
	var b LimitedBuffer
	b.Limit = 4
	if n, _ := b.Write([]byte("abcdef")); n != 6 || b.String() != "abcd" || !b.overflow {
		t.Fatalf("n=%d buffered=%q overflow=%t", n, b.String(), b.overflow)
	}
}

// A hook that starts a background job must not wait for it, whichever of the
// hook's outputs the job keeps open: the hook ends when its program exits,
// and the job is stopped with the process group.
func TestRunnerStopsBackgroundJobs(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "survivor")
	for name, script := range map[string]string{
		"stdout":  "(sleep 1; touch '" + marker + "') 2>/dev/null & echo started",
		"stderr":  "(sleep 1; touch '" + marker + "') >/dev/null & echo started",
		"both":    "(sleep 1; touch '" + marker + "') & echo started",
		"neither": "(sleep 1; touch '" + marker + "') >/dev/null 2>&1 & echo started",
	} {
		start := time.Now()
		out, err := (Exec{}).Run(t.Context(), "/bin/sh", []string{"-c", script}, nil)
		if elapsed := time.Since(start); err != nil || string(out) != "started\n" || elapsed > WaitDelay/2 {
			t.Fatalf("%s: %q %v after %v", name, out, err, elapsed)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("background job outlived its hook")
	}
}

// A process that leaves the hook's process group (setsid) cannot be stopped
// with it. If it keeps the output open, the hook fails after WaitDelay with
// a message that says so.
func TestRunnerReportsOutputHeldOutsideItsGroup(t *testing.T) {
	if ready := os.Getenv("NETSHIFT_ESCAPE_CHILD"); ready != "" {
		if _, err := syscall.Setsid(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(ready, nil, 0600); err != nil {
			os.Exit(2)
		}
		time.Sleep(WaitDelay + 5*time.Second) // holds the inherited output open
		os.Exit(0)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	// The shell exits only once the child has left its process group.
	script := `"$0" -test.run='^TestRunnerReportsOutputHeldOutsideItsGroup$' &
		while [ ! -e "$1" ]; do sleep 0.05; done; echo started`
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second) // should the child fail to start
	defer cancel()
	start := time.Now()
	_, err := (Exec{}).Run(ctx, "/bin/sh", []string{"-c", script, os.Args[0], ready}, []string{"NETSHIFT_ESCAPE_CHILD=" + ready})
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "outside its process group kept its output open") {
		t.Fatalf("escaped output holder: %v", err)
	}
	if elapsed < WaitDelay || elapsed > WaitDelay+4*time.Second {
		t.Fatalf("returned after %v, want about %v", elapsed, WaitDelay)
	}
}

// A home directory that is missing, not a directory, or cannot be entered is
// not used, rather than failing every program with a misleading error.
func TestRunnerIgnoresUnusableHome(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	locked := filepath.Join(dir, "locked")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(locked, 0600); err != nil {
		t.Fatal(err)
	}
	homes := []string{filepath.Join(dir, "missing"), file}
	if os.Geteuid() != 0 { // root may enter any directory
		homes = append(homes, locked)
	}
	for _, home := range homes {
		t.Setenv("HOME", home)
		if dir := workingDir(); dir != "" {
			t.Errorf("HOME=%s: working directory %q", home, dir)
		}
		if _, err := (Exec{}).Run(t.Context(), "/usr/bin/true", nil, nil); err != nil {
			t.Errorf("HOME=%s: %v", home, err)
		}
	}
}

func TestRunnerLiteralArgumentsAndTimeout(t *testing.T) {
	r := Exec{}
	literal := "$(touch /tmp/netshift-must-not-exist); hello"
	data, err := r.Run(context.Background(), "/usr/bin/printf", []string{"%s", literal}, nil)
	if err != nil || string(data) != literal {
		t.Fatal(string(data), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = r.Run(ctx, "/bin/sleep", []string{"30"}, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatal(err, time.Since(start))
	}
}
