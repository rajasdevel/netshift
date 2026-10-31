//go:build windows

package store

import (
	"os"
	"path/filepath"
)

// windowsStateDir returns the directory for state files on Windows,
// %LOCALAPPDATA%\NetShift\state, which stays on this machine; the files in
// it are private to their owner (see fsx.PrivateSDDL).
func windowsStateDir() (string, error) {
	d, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "NetShift", "state"), nil
}
