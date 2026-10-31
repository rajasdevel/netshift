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

// releaseOwnConsole closes a console window that Windows opened for this
// process alone, as it does when Task Scheduler starts the watcher, so the
// window does not stay on the desktop. A console shared with a shell, or no
// console, is left alone. The event log goes to --log-file either way, and
// programs the watcher starts get no window of their own (see proc).
func releaseOwnConsole() {
	var pids [2]uint32
	if n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids))); n == 1 {
		_, _, _ = procFreeConsole.Call()
	}
}
