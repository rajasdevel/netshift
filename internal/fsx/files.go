// Package fsx holds the careful file operations NetShift's own files need:
// profiles, state, history, the event log, and locks. Reads are bounded,
// opens refuse symlinks and special files, writes are atomic, and new
// directory entries are synced.
package fsx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// ErrTooLarge reports a file over its size limit (see ReadFileLimit).
var ErrTooLarge = errors.New("file exceeds its size limit")

// ReadFileLimit reads a whole file of at most limit bytes, so a damaged or
// hostile file cannot exhaust memory. A larger file is an ErrTooLarge error.
// limit is a whole number of MiB.
func ReadFileLimit(path string, limit int64) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return readFileLimitWindows(path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tooLarge := func() error { return fmt.Errorf("%s: %w of %d MiB", path, ErrTooLarge, limit>>20) }
	// Refuse a known oversized file without reading it; the read limit below
	// still holds for a file that grows or does not report its size.
	if info, err := f.Stat(); err == nil && info.Size() > limit {
		return nil, tooLarge()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, tooLarge()
	}
	return data, nil
}

// OpenRegular opens path with flag, creating it with mode 0600 if absent, and
// returns it with its metadata. It refuses a symlink in the final element and
// anything but a regular file. Both checks are made on the open itself
// (O_NOFOLLOW, then fstat), so the path cannot be swapped between a check and
// the use, and a FIFO cannot block the open (O_NONBLOCK).
func OpenRegular(path string, flag int) (*os.File, fs.FileInfo, error) {
	if runtime.GOOS == "windows" {
		return openRegularWindows(path, flag)
	}
	f, err := os.OpenFile(path, flag|os.O_CREATE|openNoFollow|openNonblock, 0600)
	if err != nil {
		if openRefused(err) {
			return nil, nil, fmt.Errorf("%s is not a regular file", path)
		}
		return nil, nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", path)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// EnsureDir creates dir and any missing parents with mode 0700, as
// os.MkdirAll does, and then syncs the parent of every directory it created,
// so a file written into a new state directory cannot vanish with it in a
// crash. An existing dir costs one stat.
func EnsureDir(dir string) error {
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return nil
	}
	created := missingDirs(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, d := range created {
		if err := SyncDirPath(filepath.Dir(d)); err != nil {
			return err
		}
	}
	return nil
}

// missingDirs returns dir and each of its ancestors that does not exist yet,
// outermost first: the directories os.MkdirAll(dir) would create.
func missingDirs(dir string) []string {
	var missing []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); !errors.Is(err, fs.ErrNotExist) {
			break
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}
	return missing
}

// SyncDirPath opens dir and syncs it (see syncDirectory).
func SyncDirPath(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return syncDirectory(d)
}

// syncRoot syncs the directory that root is a handle on, rather than whatever
// its path names now, making a rename made through root durable.
func syncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return syncDirectory(d)
}

// SameFile reports whether both paths name one existing file, including
// case-insensitive aliases and hard links.
func SameFile(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

// AtomicWrite replaces path with data and mode durably: it writes and syncs a
// temporary file, renames it over path, and syncs the directory. Readers see
// the old or the new content, never a mix. A symlink at path is refused rather
// than replaced. A missing directory is created, and its parent synced.
//
// The check, the temporary file, the rename, and the final directory sync
// resolve names inside one handle on the directory (os.Root), so the
// directory cannot be swapped between them and none can follow a link out of
// it. rename(2) replaces rather than follows a symlink, so a link created
// after the check is never written through. Windows has its own
// implementation (atomicWriteWindows).
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return atomicWriteWindows(path, data, mode)
	}
	dir, name := filepath.Dir(path), filepath.Base(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink destination: %s", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("write %s: %w", path, err)
	}
	temp := ".netshift-" + rand.Text()
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer root.Remove(temp) // fails harmlessly once renamed
	// Chmod sets the exact mode, which the umask could narrow at creation.
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = root.Rename(temp, name)
	}
	if err == nil {
		err = syncRoot(root)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// WriteNew writes data to a new private file (mode 0600) at path, never over
// an existing file or through a symlink, even after a racing writer. It
// writes and syncs a temporary file in the same directory and then links it
// into place, so a failed write leaves nothing at path to block a retry. An
// existing path is an error that matches fs.ErrExist. A missing directory is
// created with mode 0700.
func WriteNew(path string, data []byte) error {
	if runtime.GOOS == "windows" {
		return writeNewWindows(path, data)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // mode 0600
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// link, unlike rename, fails when path exists, and never follows a
	// symlink in its place.
	if err = os.Link(temp, path); err != nil {
		return err
	}
	// The file's data is synced; making its name durable is best effort.
	_ = SyncDirPath(dir)
	return nil
}
