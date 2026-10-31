//go:build !windows

package cli

// releaseOwnConsole does nothing: only Windows opens a console window for a
// background service.
func releaseOwnConsole() {}
