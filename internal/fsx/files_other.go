//go:build !(darwin || linux || windows)

package fsx

import (
	"errors"
	"io/fs"
	"os"
)

// errUnsupportedPlatform explains why durable writes are unavailable.
// Profiles still validate, so they can be edited anywhere.
var errUnsupportedPlatform = errors.New("NetShift runs on macOS, Linux, and Windows only")

func openRead(path string) (*os.File, error) { return os.Open(path) }

// openNoFollow uses the plain open; OpenRegular's fstat check still refuses
// non-regular files.
func openNoFollow(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag|os.O_CREATE, 0600)
}

func Rename(from, to string) error { return os.Rename(from, to) }

func isLink(info fs.FileInfo) bool { return info.Mode()&fs.ModeSymlink != 0 }

// Durable writes are unavailable here (see errUnsupportedPlatform).
func replaceFile(*os.Root, string, string, string) error { return errUnsupportedPlatform }

func syncDirectory(*os.File) error { return errUnsupportedPlatform }

// TryLockFile always succeeds: there is no advisory lock here, so log
// rotation relies on its file identity check alone.
func TryLockFile(*os.File) bool { return true }
