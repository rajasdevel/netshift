//go:build windows

package discovery

import (
	"net"
	"os"
	"syscall"
	"testing"
)

// Winsock codes read like their Unix counterparts.
func TestWinsockErrorsAreClassified(t *testing.T) {
	op := func(name string, code syscall.Errno) *net.OpError {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError(name, code)}
	}
	for code, want := range map[syscall.Errno]string{10061: "connection refused", 10051: "network unreachable", 10065: "network unreachable", 10054: "connection reset"} {
		if got := connectionFailure(op("connectex", code)); got != want {
			t.Errorf("%d: %q, want %q", code, got, want)
		}
	}
}
