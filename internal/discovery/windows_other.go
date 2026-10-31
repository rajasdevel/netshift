//go:build !windows

package discovery

// Stubs for the Windows-only functions that shared code names inside
// if runtime.GOOS == "windows" blocks. Those blocks are compiled out on
// other platforms, so none of these is ever linked into their binaries.

func winsockRefused(error) bool     { return false }
func winsockUnreachable(error) bool { return false }
func winsockReset(error) bool       { return false }
