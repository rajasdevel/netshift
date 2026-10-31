//go:build !(darwin || linux || windows)

package proc

import (
	"errors"
	"os/exec"
)

// errUnsupportedPlatform explains why programs cannot run here.
var errUnsupportedPlatform = errors.New("NetShift runs on macOS, Linux, and Windows only")

// groupSys is empty: no program starts here.
type groupSys struct{}

// ContainProcess cannot contain a program here, so the command fails to
// start rather than run without its timeout guarantees.
func ContainProcess(cmd *exec.Cmd) *Group {
	cmd.Err = errUnsupportedPlatform
	return &Group{cmd: cmd}
}

func (g *Group) start() error { return g.cmd.Start() }

func (g *Group) stop() {}

// Programs cannot run here, so they never get a working directory.
func searchableDir(string) bool { return false }
