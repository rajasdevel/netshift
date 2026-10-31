//go:build !windows

package doctor

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

import (
	"context"

	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

func toastHelper() string { return "" }

func taskServiceState(context.Context, proc.Runner, service.Spec) (string, string, bool) {
	return "", "", false
}
