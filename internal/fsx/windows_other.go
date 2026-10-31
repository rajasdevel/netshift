//go:build !windows

package fsx

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

import (
	"io/fs"
	"os"
)

func readFileLimitWindows(string, int64) ([]byte, error)            { return nil, nil }
func openRegularWindows(string, int) (*os.File, fs.FileInfo, error) { return nil, nil, nil }
func atomicWriteWindows(string, []byte, os.FileMode) error          { return nil }
func writeNewWindows(string, []byte) error                          { return nil }

// Rename moves from to to, replacing to (see the Windows version).
func Rename(from, to string) error { return os.Rename(from, to) }
