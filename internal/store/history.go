package store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// HistoryRecord is one line of the append-only audit history: an intent saved
// before an external write, or what became of it. Status is one of:
//
//   - intent: an Azure rule write is about to be sent.
//   - verified: the write was read back and matched; reconciled: an
//     interrupted write was found applied; superseded: a newer intent
//     replaced it; failed: the target update failed.
//   - baseline: the rule's sources when NetShift first saw them, or after an
//     unfinished intent for another address.
//   - device_intent, device_create_intent, device_delete_intent,
//     device_verified, device_reconciled, device_superseded: the same
//     lifecycle for per-identity device registry tags and PostgreSQL rules.
//   - metadata_intent, metadata_verified, metadata_reconciled,
//     metadata_superseded: the same lifecycle for shared history tags.
//
// The Azure action code writes these values; the history command shows them.
type HistoryRecord struct {
	Identity      string    `json:"identity,omitempty"` // user@host that wrote the record
	Tag           string    `json:"tag,omitempty"`      // Azure tag, for metadata records
	BeforeValue   string    `json:"before_value,omitempty"`
	AfterValue    string    `json:"after_value,omitempty"`
	At            time.Time `json:"at"`
	OperationID   string    `json:"operation_id,omitempty"` // links an intent to its outcome
	Status        string    `json:"status"`
	Action        string    `json:"action"`
	Target        string    `json:"target"`
	ResourceID    string    `json:"resource_id"`
	IP            string    `json:"ip"` // address being applied
	RemovedIPs    []string  `json:"removed_ips,omitempty"`
	BeforeSources []string  `json:"before_sources,omitempty"`
	AfterSources  []string  `json:"after_sources,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// maxHistoryRecord bounds one history line, including its newline.
const maxHistoryRecord = 1 << 20

// HistoryPath returns the history file that belongs to a state file.
func HistoryPath(state string) string {
	return strings.TrimSuffix(state, filepath.Ext(state)) + ".history.jsonl"
}

// OperationID returns a random 128-bit identifier in hex. Since Go 1.24,
// crypto/rand.Read never returns an error.
func OperationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// AppendHistory appends r durably: the line is synced before it returns, and
// so is the directory when the file was empty. It refuses to write after an
// incomplete last line, which needs a person to look at it, and refuses a
// symlink or any other non-regular file at path. The caller holds the profile
// lock, so it is the only writer.
func AppendHistory(path string, r HistoryRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxHistoryRecord {
		return errors.New("history: entry exceeds 1 MiB")
	}
	dir := filepath.Dir(path)
	if err = fsx.EnsureDir(dir); err != nil {
		return fmt.Errorf("history: %w", err)
	}
	f, info, err := fsx.OpenRegular(path, os.O_RDWR|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	defer f.Close()
	size := info.Size()
	if size > 0 {
		var last [1]byte
		if _, err = f.ReadAt(last[:], size-1); err != nil {
			return fmt.Errorf("history: %w", err)
		}
		if last[0] != '\n' {
			return fmt.Errorf("history: %s ends with an incomplete record; preserve and repair it before further writes", path)
		}
	}
	if err = appendLine(f, size, data); err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if size == 0 {
		// This may be the record that created the file: make its directory
		// entry durable too.
		if err = fsx.SyncDirPath(dir); err != nil {
			return fmt.Errorf("history: %w", err)
		}
	}
	return nil
}

// appendFile is the part of *os.File that appendLine uses.
type appendFile interface {
	Write([]byte) (int, error)
	Truncate(size int64) error
	Sync() error
}

// appendLine writes line at the end of f, an O_APPEND file of size bytes, and
// syncs it. A failed or short write, as when the disk fills, is undone: f is
// truncated back to size and synced before the error returns, so a partial
// line cannot make every later append refuse. This is safe only for the
// file's single writer.
func appendLine(f appendFile, size int64, line []byte) error {
	// os.File.Write reports a short write as an error.
	if _, err := f.Write(line); err != nil {
		if undo := f.Truncate(size); undo != nil {
			return errors.Join(err, fmt.Errorf("remove partial record: %w", undo))
		}
		return errors.Join(err, f.Sync())
	}
	return f.Sync()
}

// ReadHistory returns the last limit records, oldest first, optionally only
// those for one target. A missing file is an empty history, never nil; a
// malformed line is an error.
func ReadHistory(path string, limit int, target string) ([]HistoryRecord, error) {
	if limit < 1 {
		return nil, errors.New("history limit must be positive")
	}
	records := []HistoryRecord{}
	next := 0 // Once the ring is full, records[next] is the oldest.
	for r, err := range ScanHistory(path) {
		if err != nil {
			return nil, err
		}
		if target != "" && r.Target != target {
			continue
		}
		if len(records) < limit {
			records = append(records, r)
		} else {
			records[next] = r
			next = (next + 1) % limit
		}
	}
	if next == 0 {
		return records, nil
	}
	return slices.Concat(records[next:], records[:next]), nil
}

// ScanHistory streams the audit journal, oldest record first, without holding
// it in memory. A missing journal is empty. The sequence stops after the
// first unreadable line, which it yields as an error.
func ScanHistory(path string) iter.Seq2[HistoryRecord, error] {
	return func(yield func(HistoryRecord, error) bool) {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			yield(HistoryRecord{}, err)
			return
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), maxHistoryRecord+1)
		for line := 1; scan.Scan(); line++ {
			var r HistoryRecord
			if err = json.Unmarshal(scan.Bytes(), &r); err != nil {
				yield(HistoryRecord{}, fmt.Errorf("history %s line %d: %w", path, line, err))
				return
			}
			if !yield(r, nil) {
				return
			}
		}
		if err = scan.Err(); err != nil {
			yield(HistoryRecord{}, fmt.Errorf("history %s: %w", path, err))
		}
	}
}
