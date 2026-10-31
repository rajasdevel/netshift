//go:build !windows

package service

import (
	"context"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/proc"
)

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

func platformHost(h Host) Host { return h }

func platformSpec(config.Config, string, string, Host) (Spec, bool, error) { return Spec{}, false, nil }

func platformRender(Spec) ([]byte, bool, error) { return nil, false, nil }

func platformControl(context.Context, proc.Runner, Spec, string) ([]byte, bool, error) {
	return nil, false, nil
}

func platformLoaded(context.Context, proc.Runner, Spec) (bool, bool, error) { return false, false, nil }

func platformInstall(context.Context, Spec, InstallOptions, Host, proc.Runner, config.Config, []byte) (bool, error) {
	return false, nil
}

func unregister(context.Context, proc.Runner, Spec) error { return nil }
