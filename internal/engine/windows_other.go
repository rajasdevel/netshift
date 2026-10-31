//go:build !windows

package engine

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

import (
	"io"
	"time"
)

// notifyTimeout bounds one notification helper.
const notifyTimeout = 5 * time.Second

func toastCommand(string, string) (string, []string, []string) { return "", nil, nil }

func printCreated(io.Writer, string, int, string) {}
