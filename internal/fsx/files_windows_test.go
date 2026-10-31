//go:build windows

package fsx

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// symlink creates a file symlink, or skips the test where Windows does not
// allow this account to (without administrator rights or Developer Mode).
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
}

// junction creates a directory junction, which needs no privilege.
func junction(t *testing.T, target, link string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}

func TestAtomicWriteReplacesAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, content := range []string{"first", "second"} {
		if err := AtomicWrite(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != content {
			t.Fatalf("content %q, %v", data, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

// A symlink or junction at the destination is refused, never written
// through; the directory of the file may itself be a link.
func TestAtomicWriteRefusesLinksAtTheDestination(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(dir, "target")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	junction(t, targetDir, filepath.Join(dir, "junction"))
	if err := AtomicWrite(filepath.Join(dir, "junction"), []byte("bad"), 0600); err == nil {
		t.Fatal("replaced a junction")
	}
	// The directory may be a junction, as a relocated state directory is.
	if err := AtomicWrite(filepath.Join(dir, "junction", "state.json"), []byte("{}"), 0600); err != nil {
		t.Fatalf("write through a junction directory: %v", err)
	}
	symlink(t, victim, filepath.Join(dir, "link"))
	if err := AtomicWrite(filepath.Join(dir, "link"), []byte("bad"), 0600); err == nil {
		t.Fatal("followed a symlink")
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatal("target changed")
	}
}

// NetShift's readers share delete access, so the watcher can replace the
// state file while status or doctor reads it.
func TestAtomicWriteReplacesWhileReadersHoldTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := AtomicWrite(path, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := openRead(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = AtomicWrite(path, []byte("1"), 0600); err != nil {
		t.Fatalf("replace while a reader holds the file: %v", err)
	}
	if data, _ := io.ReadAll(held); string(data) != "0" {
		t.Fatalf("open reader sees %q, want the old content", data)
	}
	_ = held.Close()

	stop := make(chan struct{})
	var readers sync.WaitGroup
	var readErr error
	readers.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := ReadFileLimit(path, 1<<20); err != nil && !errors.Is(err, os.ErrNotExist) {
				readErr = err
				return
			}
		}
	})
	for i := range 100 {
		if err = AtomicWrite(path, []byte(strings.Repeat("x", i)), 0600); err != nil {
			break
		}
	}
	close(stop)
	readers.Wait()
	if err != nil || readErr != nil {
		t.Fatalf("write: %v; read: %v", err, readErr)
	}
}

func TestOpenRegularRefusesLinksDirectoriesAndDevices(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	junction(t, dir, filepath.Join(dir, "junction"))
	refused := []string{filepath.Join(dir, "junction"), dir, os.DevNull}
	if os.Symlink(victim, filepath.Join(dir, "link")) == nil && os.Symlink(filepath.Join(dir, "created"), filepath.Join(dir, "dangling")) == nil {
		refused = append(refused, filepath.Join(dir, "link"), filepath.Join(dir, "dangling"))
	}
	for _, path := range refused {
		for _, flag := range []int{os.O_RDWR, os.O_WRONLY | os.O_APPEND, os.O_RDWR | os.O_APPEND} {
			if f, _, err := OpenRegular(path, flag); err == nil {
				f.Close()
				t.Errorf("%s (flag %#x): opened", path, flag)
			}
		}
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Lstat(filepath.Join(dir, "created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created a file through a dangling symlink")
	}
}

// Log rotation renames the log while writers have it open.
func TestOpenFilesCanBeRenamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	f, _, err := OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := openRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rename an open log: %v", err)
	}
}

// Append-only handles write at the end, whoever else writes; the history's
// read-write handle starts at the end and can truncate.
func TestAppendModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := os.WriteFile(path, []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, _, err := OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _, err := OpenRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, w := range []*os.File{a, b, a} {
		if _, err = w.Write([]byte("line\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err = a.Sync(); err != nil {
		t.Fatalf("sync an append-only handle: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "start\nline\nline\nline\n" {
		t.Fatalf("appended %q", data)
	}

	h, info, err := OpenRegular(path, os.O_RDWR|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var last [1]byte
	if _, err = h.ReadAt(last[:], info.Size()-1); err != nil || last[0] != '\n' {
		t.Fatalf("read the last byte: %q %v", last, err)
	}
	if _, err = h.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err = h.Truncate(info.Size()); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "start\nline\nline\nline\n" {
		t.Fatalf("after truncate %q", data)
	}
}

// The lock excludes other handles but leaves the content readable.
func TestLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.lock")
	first, _, err := OpenRegular(path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, _, err := OpenRegular(path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = LockFile(first); err != nil {
		t.Fatal(err)
	}
	if err = LockFile(second); !IsLockViolation(err) {
		t.Fatalf("second lock: %v", err)
	}
	if _, err = second.Write([]byte("readable")); err != nil {
		t.Fatalf("the lock blocks the content: %v", err)
	}
	if err = UnlockFile(first); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- LockFile(second) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("lock after unlock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LockFile waited")
	}
}
