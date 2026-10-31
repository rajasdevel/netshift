//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// syncBuffer is a bytes.Buffer that a log follower may write to while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Windows has no tail: NetShift prints the last lines itself and follows the
// file across rotation and truncation, as tail -F does.
func TestFileLogReaderTailsAndFollowsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	entry := func(event string) string { return `{"time":"t","event":"` + event + `"}` + "\n" }
	if err := os.WriteFile(path, []byte(entry("one")+entry("two")+entry("three")+`{"time":"t","ev`), 0600); err != nil {
		t.Fatal(err)
	}
	old := runtimeOutput
	t.Cleanup(func() { runtimeOutput = old })
	out := &syncBuffer{}
	runtimeOutput = out
	if err := readFileLog(t.Context(), path, 2, false, true, followPoll); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != entry("two")+entry("three") {
		t.Fatalf("last lines: %q", got)
	}
	appendTo := func(p, text string) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			_, err = f.WriteString(text)
			err = errors.Join(err, f.Close())
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		out = &syncBuffer{}
		runtimeOutput = out
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error)
		go func() { done <- readFileLog(ctx, path, 1, true, true, time.Second) }()
		// Each step falls between two polls, at 1.5s, 2.5s, and so on.
		time.Sleep(1500 * time.Millisecond)
		appendTo(path, `ent":"four"}`+"\n") // completes the partial line
		time.Sleep(time.Second)
		if err := os.Rename(path, path+".1"); err != nil {
			t.Fatal(err)
		}
		appendTo(path+".1", entry("five")) // the last entry of the rotated file
		if err := os.WriteFile(path, []byte(entry("six")), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if err := os.WriteFile(path, []byte(entry("7")), 0600); err != nil { // truncated and rewritten, shorter
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	if got, want := out.String(), entry("three")+entry("four")+entry("five")+entry("six")+entry("7"); got != want {
		t.Fatalf("followed:\n%s\nwant:\n%s", got, want)
	}
}
