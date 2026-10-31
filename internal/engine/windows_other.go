//go:build !windows

package engine

import "io"

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

func toastCommand(string, string) (string, []string, []string, error) { return "", nil, nil, nil }

func printCreated(io.Writer, string, int, string) {}
