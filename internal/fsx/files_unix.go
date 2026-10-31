//go:build darwin || linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// openRead opens path for reading.
func openRead(path string) (*os.File, error) { return os.Open(path) }

// openNoFollow opens path with flag for OpenRegular, creating it with mode
// 0600 if absent. O_NOFOLLOW makes the open itself refuse a symlink in the
// final path element, so a link cannot be swapped in between a check and the
// open. O_NONBLOCK keeps a planted FIFO from blocking the open; it does not
// change reads or writes on a regular file. A symlink (ELOOP), or a FIFO or
// device with nothing on the other end (ENXIO), is errNotRegular.
func openNoFollow(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENXIO) {
		return nil, errNotRegular
	}
	return f, err
}

// Rename moves from to to, replacing to. rename(2) replaces a symlink at
// to rather than writing through it.
func Rename(from, to string) error { return os.Rename(from, to) }

// isLink reports whether info, from Lstat, describes a symlink.
func isLink(info fs.FileInfo) bool { return info.Mode()&fs.ModeSymlink != 0 }

// replaceFile renames temp over name inside root.
func replaceFile(root *os.Root, _, temp, name string) error { return root.Rename(temp, name) }

// syncDirectory makes creations and renames in the open directory d durable.
// File systems that cannot sync a directory report EINVAL, ENOTSUP, or
// ENOSYS; those are not failures.
func syncDirectory(d *os.File) error {
	err := d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
		return nil
	}
	return err
}

// TryLockFile takes an exclusive flock(2) on f without waiting and reports
// whether it did. Closing f releases the lock.
func TryLockFile(f *os.File) bool {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}
