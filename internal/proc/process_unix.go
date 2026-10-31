//go:build darwin || linux

package proc

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// groupSys is the process group's ID: the program's PID, once started.
type groupSys struct{ pgid int }

// ContainProcess prepares cmd to start in its own process group, so a
// timeout or cancellation kills the program and everything it started.
func ContainProcess(cmd *exec.Cmd) *Group {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return &Group{cmd: cmd}
}

// start starts the program; Setpgid makes it the leader of a new group.
func (g *Group) start() error {
	err := g.cmd.Start()
	if err == nil {
		g.sys.pgid = g.cmd.Process.Pid
	}
	return err
}

// stop kills anything left in the program's process group.
func (g *Group) stop() {
	if g.sys.pgid > 0 {
		_ = syscall.Kill(-g.sys.pgid, syscall.SIGKILL)
	}
}

// accessSearch is X_OK for access(2): on a directory, permission to enter it.
const accessSearch = 0x1

// searchableDir reports whether dir is a directory this process may make its
// working directory.
func searchableDir(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir() && syscall.Access(dir, accessSearch) == nil
}
