//go:build !(darwin || linux)

package store

import "errors"

// Lock refuses: state locking needs flock.
func Lock(string) (func(), error) {
	return nil, errors.New("NetShift runs on macOS and Linux only")
}
