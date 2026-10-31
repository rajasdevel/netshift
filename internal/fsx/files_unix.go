//go:build darwin || linux

package fsx

import (
	"errors"
	"os"
	"syscall"
)

// Open flags for files NetShift appends to or locks in place (see
// OpenRegular). openNoFollow makes the open itself refuse a symlink in the
// final path element, so a link cannot be swapped in between a check and the
// open. openNonblock keeps a planted FIFO from blocking the open; it does not
// change reads or writes on a regular file.
const (
	openNoFollow = syscall.O_NOFOLLOW
	openNonblock = syscall.O_NONBLOCK
)

// openRefused reports whether an open with openNoFollow and openNonblock
// failed because the path is not a regular file: a symlink (ELOOP), or a
// FIFO or device with nothing on the other end (ENXIO).
func openRefused(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENXIO)
}

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
