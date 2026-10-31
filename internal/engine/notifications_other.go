//go:build !windows

package engine

import "time"

// notifyTimeout bounds one notification helper.
const notifyTimeout = 5 * time.Second
