// Package eventlog writes the JSON event log, one object per line, and
// rotates a log file safely when several watchers share it.
package eventlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// Logger writes the JSON event log: one object per line holding the caller's
// fields plus "event" (the event name) and "time" (RFC 3339, UTC, whole
// seconds). The logs command parses these two keys, so their names and the
// time layout are stable.
type Logger struct {
	Out io.Writer        // destination; nil discards entries
	Now func() time.Time // clock for entry times; nil means time.Now
}

// Log writes one entry. It does not modify fields; "event" and "time" take
// precedence over fields with the same keys.
func (l Logger) Log(event string, fields map[string]any) {
	if l.Out == nil {
		return
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	at := now().UTC().Format(time.RFC3339)
	entry := make(map[string]any, len(fields)+2)
	maps.Copy(entry, fields)
	entry["event"] = event
	entry["time"] = at
	line, err := json.Marshal(entry)
	if err != nil {
		// Fields are plain data. Should one fail to encode, keep the event
		// and the reason rather than writing an empty line.
		line, _ = json.Marshal(map[string]string{"event": event, "time": at, "log_error": err.Error()})
	}
	// The event log is best effort, so a write error is deliberately ignored:
	// a full disk or closed pipe must not stop monitoring or fail an action
	// whose progress is already durable in the state file and history.
	_, _ = l.Out.Write(append(line, '\n'))
}

// RotatingWriter is the --log-file writer. Linux services log to the user's
// journal instead; this bounds long-lived macOS logs. Each Write appends one
// entry; when the entry would grow the file past MaxBytes, the file first
// becomes Path+".1", replacing the previous backup. It never writes through a
// symlink or to anything but a regular file. Several processes may share one
// Path (see rotate).
type RotatingWriter struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
}

// Write appends p as one entry, rotating first if needed. The file is
// reopened for every entry, so it may be moved or removed between writes.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if int64(len(p)) > w.MaxBytes {
		return 0, errors.New("log entry exceeds log size limit")
	}
	if err := os.MkdirAll(filepath.Dir(w.Path), 0700); err != nil {
		return 0, err
	}
	f, info, err := fsx.OpenRegular(w.Path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return 0, fmt.Errorf("log: %w", err)
	}
	if info.Size()+int64(len(p)) > w.MaxBytes {
		if err = w.rotate(f, info); err != nil {
			return 0, err
		}
		if f, _, err = fsx.OpenRegular(w.Path, os.O_WRONLY|os.O_APPEND); err != nil {
			return 0, fmt.Errorf("log: %w", err)
		}
	}
	n, err := f.Write(p)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return n, err
}

// rotate renames the full log f, opened from Path with metadata info, to
// Path+".1", and closes f. Another process sharing Path may have rotated it
// since f was opened; renaming Path then would move that process's fresh file
// over the full backup. So rotate renames only while it holds an exclusive
// lock on f and f is still the file at Path. Every rotator follows the same
// rule, so they never both rename one file. A process that loses the race
// leaves the rename to the winner, and its entry goes to the new file or,
// at worst, the backup.
func (w *RotatingWriter) rotate(f *os.File, info fs.FileInfo) error {
	defer f.Close() // nothing was written to it; closing releases the lock
	if !fsx.TryLockFile(f) {
		return nil // another process is rotating this file
	}
	current, err := os.Lstat(w.Path)
	if err != nil || !os.SameFile(info, current) {
		return nil // already rotated; the next open finds or creates the new file
	}
	return os.Rename(w.Path, w.Path+".1")
}
