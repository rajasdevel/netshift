package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/fsx"
)

func TestStateSizeIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse file: the size check must not need to read it.
	if err = errors.Join(f.Truncate(maxStateBytes+1), f.Close()); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if !errors.Is(err, fsx.ErrTooLarge) || !strings.Contains(err.Error(), "preserve it") || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("oversized state: %v", err)
	}
	if info, _ := os.Stat(path); info.Size() != maxStateBytes+1 {
		t.Fatal("oversized state was modified")
	}
}

// A state file that spells out zero times, which writes omit, still loads.
func TestStateWithExplicitZeroTimesLoads(t *testing.T) {
	const earlier = `{
  "identity": "sam@laptop",
  "version": 1,
  "ip": "8.8.8.8",
  "connectivity": "online",
  "candidate_ip": "8.8.4.4",
  "candidate_count": 1,
  "last_event": {"type": "ip_changed", "ip": "8.8.8.8", "previous_ip": "1.1.1.1", "at": "2026-10-01T12:00:00Z"},
  "actions": {
    "allow": {
      "verification": {"action_completed_at": "2026-10-01T12:00:01Z", "event": {"type": "ip_changed", "ip": "8.8.8.8", "at": "2026-10-01T12:00:00Z"}, "fingerprint": "abc"},
      "last_checks": [{"name": "db", "reachable": false, "error": "refused", "at": "2026-10-01T12:00:02Z"}],
      "notice": {"failures": 3, "alerted": true, "attempted_at": "2026-10-01T12:00:03Z", "attempted_kind": "failure"},
      "shared_history": {"nsg-1": {"value": "{}", "verified_at": "0001-01-01T00:00:00Z"}},
      "pending": {"type": "reconcile", "ip": "8.8.8.8", "at": "2026-10-01T12:00:00Z"},
      "attempts": 2,
      "retry_at": "0001-01-01T00:00:00Z",
      "last_success": "0001-01-01T00:00:00Z",
      "targets": {"one": {"history_initialized": true, "applied_ip": "8.8.8.8", "verified_at": "0001-01-01T00:00:00Z"}}
    }
  }
}
`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(earlier), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Actions["allow"]
	if s.IP != "8.8.8.8" || s.CandidateCount != 1 || s.LastEvent.PreviousIP != "1.1.1.1" || a.Attempts != 2 ||
		!a.Notice.Alerted || a.Pending.Type != "reconcile" || !a.RetryAt.IsZero() || !a.Targets["one"].HistoryInitialized ||
		a.Verification.Event.At != time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("lost fields: %+v", s)
	}
	if err = Save(path, s); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(s)
	after, _ := json.Marshal(again)
	if string(before) != string(after) {
		t.Fatalf("round trip changed state:\n%s\n%s", before, after)
	}
}

// shortWriteFile writes only half of each line, then fails, as a write does
// when the disk fills.
type shortWriteFile struct{ *os.File }

func (f shortWriteFile) Write(p []byte) (int, error) {
	n, _ := f.File.Write(p[:len(p)/2])
	return n, syscall.ENOSPC
}

// A failed append leaves no partial line, so the next append works without
// manual repair.
func TestHistoryAppendRollsBackAPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.history.jsonl")
	if err := AppendHistory(path, HistoryRecord{Status: "verified", Target: "first"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	f, info, err := fsx.OpenRegular(path, os.O_RDWR|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	err = appendLine(shortWriteFile{f}, info.Size(), []byte(`{"status":"verified","target":"second"}`+"\n"))
	_ = f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("short write: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("partial line kept: %q", after)
	}
	if err = AppendHistory(path, HistoryRecord{Status: "verified", Target: "third"}); err != nil {
		t.Fatalf("append after a failed write: %v", err)
	}
	records, err := ReadHistory(path, 10, "")
	if err != nil || len(records) != 2 || records[1].Target != "third" {
		t.Fatalf("%+v %v", records, err)
	}
}

// fakeAppendFile records what appendLine does with a failed write.
type fakeAppendFile struct {
	calls       []string
	truncateErr error
}

func (f *fakeAppendFile) Write(p []byte) (int, error) {
	f.calls = append(f.calls, "write")
	return 0, errors.New("disk full")
}
func (f *fakeAppendFile) Truncate(size int64) error {
	f.calls = append(f.calls, "truncate "+strconv.FormatInt(size, 10))
	return f.truncateErr
}
func (f *fakeAppendFile) Sync() error { f.calls = append(f.calls, "sync"); return nil }

func TestAppendLineTruncatesAndSyncsBeforeReturning(t *testing.T) {
	f := &fakeAppendFile{}
	if err := appendLine(f, 42, []byte("x\n")); err == nil || strings.Join(f.calls, ",") != "write,truncate 42,sync" {
		t.Fatalf("%v %v", f.calls, err)
	}
	f = &fakeAppendFile{truncateErr: errors.New("read-only")}
	if err := appendLine(f, 42, []byte("x\n")); err == nil || !strings.Contains(err.Error(), "remove partial record: read-only") {
		t.Fatalf("%v %v", f.calls, err)
	}
}

func TestHistoryReadErrorsAndEmptyHistory(t *testing.T) {
	dir := t.TempDir()
	records, err := ReadHistory(filepath.Join(dir, "missing.history.jsonl"), 10, "")
	if data, _ := json.Marshal(records); err != nil || string(data) != "[]" {
		t.Fatalf("empty history is %s, %v", data, err)
	}
	path := filepath.Join(dir, "long.history.jsonl")
	if err = os.WriteFile(path, []byte(strings.Repeat("x", maxHistoryRecord+2)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadHistory(path, 10, ""); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("scanner error without the path: %v", err)
	}
	if err = os.WriteFile(path, []byte("{\"status\":\"verified\"}\n{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = AppendHistory(path, HistoryRecord{}); err == nil || !strings.HasPrefix(err.Error(), "history: ") {
		t.Fatalf("incomplete record: %v", err)
	}
}
