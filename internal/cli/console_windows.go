//go:build windows

package cli

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
)

// windowsStarterCommand is the command of the profile init command writes on
// Windows, as in config/windows.example.json: it prints the NETSHIFT_*
// variables.
func windowsStarterCommand() []string { return []string{"cmd.exe", "/d", "/c", "set NETSHIFT_"} }

// startedByTask is set by the --scheduled-task option, which only the
// scheduled task passes.
var startedByTask bool

// releaseOwnConsole closes the console window that Windows opens for the
// watcher when Task Scheduler starts it, so the window does not stay on the
// desktop. It acts only for the scheduled task, and only on a console no
// other process shares: a watch started by hand keeps its window, Ctrl+C,
// and standard error. The task's event log goes to --log-file, and programs
// the watcher starts get no window of their own (see proc).
func releaseOwnConsole() {
	if !startedByTask {
		return
	}
	var pids [2]uint32
	if n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids))); n == 1 {
		_, _, _ = procFreeConsole.Call()
	}
}
