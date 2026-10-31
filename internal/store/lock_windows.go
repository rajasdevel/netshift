//go:build windows

package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// Lock takes the single-writer lock beside the state file without waiting
// (LockFileEx); the returned function releases it.
func Lock(path string) (func(), error) {
	if err := fsx.EnsureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, _, err := fsx.OpenRegular(path+".lock", os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = fsx.LockFile(f); err != nil {
		f.Close()
		if fsx.IsLockViolation(err) {
			return nil, fmt.Errorf("another NetShift writer owns this profile: %w", err)
		}
		return nil, fmt.Errorf("lock %s: %w", path+".lock", err)
	}
	return func() { _ = fsx.UnlockFile(f); _ = f.Close() }, nil
}
