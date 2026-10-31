//go:build darwin || linux

package eventlog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// Rotation renames the log over its backup. rename(2) replaces a planted
// backup symlink instead of writing through it.
func TestLogRotationReplacesBackupSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.log")
	if err := os.Symlink(victim, path+".1"); err != nil {
		t.Fatal(err)
	}
	w := &RotatingWriter{Path: path, MaxBytes: 16}
	for range 3 {
		if _, err := w.Write([]byte("0123456789\n")); err != nil {
			t.Fatal(err)
		}
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatal("rotation wrote through the backup symlink")
	}
	if info, err := os.Lstat(path + ".1"); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("backup: %v %v", info, err)
	}
}

// Two processes sharing one log can both find it full. Only the one that
// still holds the file at Path, and holds its lock, renames it; the other
// must not move the fresh log over the full backup.
func TestLogRotationIsSafeBetweenProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	full := []byte("0123456789\n")
	first := &RotatingWriter{Path: path, MaxBytes: 16}
	second := &RotatingWriter{Path: path, MaxBytes: 16}
	if _, err := first.Write(full); err != nil {
		t.Fatal(err)
	}
	// The second process opens the full log and is about to rotate it ...
	f, info, err := fsx.OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	// ... when the first one rotates it and starts a new log.
	if _, err = first.Write([]byte("fresh\n")); err != nil {
		t.Fatal(err)
	}
	if err = second.rotate(f, info); err != nil {
		t.Fatal(err)
	}
	if backup, _ := os.ReadFile(path + ".1"); string(backup) != string(full) {
		t.Fatalf("backup replaced: %q", backup)
	}
	if current, _ := os.ReadFile(path); string(current) != "fresh\n" {
		t.Fatalf("log: %q", current)
	}

	// A rotation in progress elsewhere holds the lock; this one stands back.
	held, _, err := fsx.OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if !fsx.TryLockFile(held) {
		t.Fatal("lock")
	}
	f, info, err = fsx.OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	if err = second.rotate(f, info); err != nil {
		t.Fatal(err)
	}
	if current, _ := os.ReadFile(path); string(current) != "fresh\n" {
		t.Fatalf("rotated under another lock: %q", current)
	}
}

func TestRotatingLogIsBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.log")
	w := &RotatingWriter{Path: p, MaxBytes: 64}
	for range 100 {
		if _, err := w.Write([]byte("a bounded entry\n")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{p, p + ".1"} {
		info, err := os.Stat(name)
		if err != nil || info.Size() > 64 {
			t.Fatal(info, err)
		}
	}
}
