//go:build !(darwin || linux)

package fsx

import (
	"errors"
	"os"
)

// errUnsupportedPlatform explains why durable writes are unavailable.
// Profiles still validate, so they can be edited anywhere.
var errUnsupportedPlatform = errors.New("NetShift runs on macOS and Linux only")

// No-follow and non-blocking opens are Unix flags; elsewhere the plain open
// is used, and OpenRegular's fstat check still refuses non-regular files.
const (
	openNoFollow = 0
	openNonblock = 0
)

// openRefused is always false: the open flags it explains are not used here.
func openRefused(error) bool { return false }

// Durable writes are unavailable here (see errUnsupportedPlatform).
func syncDirectory(*os.File) error { return errUnsupportedPlatform }

// TryLockFile always succeeds: there is no advisory lock here, so log
// rotation relies on its file identity check alone.
func TryLockFile(*os.File) bool { return true }
