//go:build windows

package discovery

import (
	"errors"
	"syscall"
)

// Windows reports socket failures as Winsock codes, which the syscall.E*
// values connectionFailure checks do not match there.

func winsockRefused(err error) bool { return errors.Is(err, syscall.Errno(10061)) } // WSAECONNREFUSED

// winsockUnreachable: WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN,
// WSAEHOSTDOWN, WSAEADDRNOTAVAIL.
func winsockUnreachable(err error) bool { return isAny(err, 10051, 10065, 10050, 10064, 10049) }

// winsockReset: WSAECONNRESET, WSAECONNABORTED.
func winsockReset(err error) bool { return isAny(err, 10054, 10053) }

func isAny(err error, codes ...syscall.Errno) bool {
	for _, code := range codes {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}
