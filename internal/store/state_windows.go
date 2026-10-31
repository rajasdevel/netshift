//go:build windows

package store

import (
	"os"
	"path/filepath"
)

// windowsStateDir returns the directory for state files on Windows,
// %LOCALAPPDATA%\NetShift\state, which stays on this machine and, under the
// user's profile, is readable only by the user, SYSTEM, and administrators.
func windowsStateDir() (string, error) {
	d, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "NetShift", "state"), nil
}
