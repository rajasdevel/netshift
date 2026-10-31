//go:build windows

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/eventlog"
)

// The log and history refuse a symlink (even a dangling one), a junction,
// and a device, so none can redirect or block a write.
func TestAppendedFilesRefuseLinksAndSpecialFiles(t *testing.T) {
	writers := map[string]func(path string) error{
		"history": func(path string) error { return AppendHistory(path, HistoryRecord{Status: "verified"}) },
		"log": func(path string) error {
			_, err := (&eventlog.RotatingWriter{Path: path, MaxBytes: 1 << 10}).Write([]byte("entry\n"))
			return err
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(dir, "victim")
			if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(dir, "junction"), dir).CombinedOutput(); err != nil {
				t.Fatalf("mklink /J: %v: %s", err, out)
			}
			paths := []string{filepath.Join(dir, "junction"), os.DevNull}
			if os.Symlink(victim, filepath.Join(dir, "link")) == nil && os.Symlink(filepath.Join(dir, "created"), filepath.Join(dir, "dangling")) == nil {
				paths = append(paths, filepath.Join(dir, "link"), filepath.Join(dir, "dangling"))
			}
			for _, path := range paths {
				if err := write(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s: %v", filepath.Base(path), err)
				}
			}
			if data, _ := os.ReadFile(victim); string(data) != "keep" {
				t.Fatal("wrote through a symlink")
			}
			if _, err := os.Lstat(filepath.Join(dir, "created")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created a file through a dangling symlink")
			}
		})
	}
}
