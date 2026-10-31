//go:build darwin || linux

package proc

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ContainProcess starts cmd in its own process group so a timeout or
// cancellation kills the program and everything it started.
func ContainProcess(cmd *exec.Cmd) {
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
}

// stopProcessGroup kills anything left in cmd's process group after it exits.
func stopProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
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
