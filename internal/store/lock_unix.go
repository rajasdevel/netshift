//go:build darwin || linux

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// Lock takes the single-writer lock beside the state file without
// waiting; the returned function releases it.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, _, err := fsx.OpenRegular(path+".lock", os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another NetShift writer owns this profile: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
