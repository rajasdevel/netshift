//go:build darwin || linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteSetsModeAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netshift")
	for _, content := range []string{"first", "second"} {
		if err := AtomicWrite(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			t.Fatalf("content %q, %v", data, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("mode: %v %v", info, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

// os.Root confines the final name, not the directory path: a symlinked state
// directory, which users set up deliberately, keeps working.
func TestAtomicWriteThroughSymlinkedDirectory(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(link, "profile.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(real, "profile.json")); err != nil || string(data) != "{}" {
		t.Fatalf("%q %v", data, err)
	}
}

// A new state directory is created with every missing parent, and each new
// entry's parent is synced (see EnsureDir).
func TestAtomicWriteCreatesMissingDirectories(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "c")
	want := []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), dir}
	if got := missingDirs(dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("missing: %v", got)
	}
	if err := AtomicWrite(filepath.Join(dir, "state.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, d := range want {
		if info, err := os.Stat(d); err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("%s: %v %v", d, info, err)
		}
	}
	if got := missingDirs(dir); len(got) != 0 {
		t.Fatalf("missing after creation: %v", got)
	}
}

// The final sync uses the directory handle, so it reaches the directory the
// file was renamed in even if that directory's path has moved since.
func TestSyncRootUsesTheHandle(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err = syncRoot(root); err != nil {
		t.Fatalf("sync through the handle: %v", err)
	}
	if err = SyncDirPath(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("by path: %v", err)
	}
}

func TestAtomicWriteRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("keep"), 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(link, []byte("bad"), 0600); err == nil {
		t.Fatal("followed symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatal("target changed")
	}
}

// WriteNew never replaces a file, even one it wrote, and never writes
// through a symlink; the new file is private.
func TestWriteNewNeverReplacesOrFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := WriteNew(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if err := WriteNew(path, []byte("replacement")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("overwrote the file: %v", err)
	}
	link := filepath.Join(dir, "alias.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if WriteNew(link, []byte("replacement")) == nil {
		t.Fatal("followed symlink")
	}
	dangling := filepath.Join(dir, "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "missing.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if WriteNew(dangling, []byte("replacement")) == nil {
		t.Fatal("wrote through a dangling symlink")
	}
	if _, err := os.Lstat(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("created the dangling symlink's target")
	}
	if raw, _ := os.ReadFile(path); string(raw) != "original" {
		t.Fatal("original changed")
	}
}

// A failed write leaves nothing at the destination, so a retry succeeds, and
// no temporary file is left behind.
func TestWriteNewFailedWriteAllowsRetry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "profiles")
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.json")
	if WriteNew(path, []byte("profile")) == nil {
		t.Fatal("wrote into a read-only directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed write left a file that blocks a retry")
	}
	if err := WriteNew(path, []byte("profile")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if data, _ := os.ReadFile(path); string(data) != "profile" || len(entries) != 1 {
		t.Fatalf("retry: %q, %d entries", data, len(entries))
	}
}
