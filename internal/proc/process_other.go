//go:build !(darwin || linux)

package proc

import (
	"errors"
	"os/exec"
)

// errUnsupportedPlatform explains why programs cannot run here.
var errUnsupportedPlatform = errors.New("NetShift runs on macOS and Linux only")

// ContainProcess cannot contain a process group here, so the command fails
// to start rather than run without its timeout guarantees.
func ContainProcess(cmd *exec.Cmd) { cmd.Err = errUnsupportedPlatform }

// stopProcessGroup does nothing: ContainProcess never starts a program here.
func stopProcessGroup(*exec.Cmd) {}

// Programs cannot run here, so they never get a working directory.
func searchableDir(string) bool { return false }
