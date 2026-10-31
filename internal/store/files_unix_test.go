//go:build darwin || linux

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rajasdevel/netshift/internal/eventlog"
)

// The log and history are opened with O_NOFOLLOW and checked after opening,
// so neither a symlink (even a dangling one) nor a FIFO can redirect or block
// a write.
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
			link := filepath.Join(dir, "link")
			dangling := filepath.Join(dir, "dangling")
			fifo := filepath.Join(dir, "fifo")
			if err := errors.Join(os.Symlink(victim, link), os.Symlink(filepath.Join(dir, "created"), dangling), syscall.Mkfifo(fifo, 0600)); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{link, dangling, fifo} {
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
