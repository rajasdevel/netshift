//go:build !windows

package cli

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

import (
	"context"

	"github.com/rajasdevel/netshift/internal/config"
)

func windowsStarterCommand() []string { return nil }

var startedByTask bool

func releaseOwnConsole() {}

func readNativeLog(context.Context, config.Config, string, *logsOptions) error { return nil }
