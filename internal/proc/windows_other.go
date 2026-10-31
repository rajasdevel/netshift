//go:build !windows

package proc

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

import "os/exec"

func startProcess(cmd *exec.Cmd) error { return cmd.Start() }
