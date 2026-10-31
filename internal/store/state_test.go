package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStateAtomicPermissionsCorruptionAndLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s := New()
	s.IP = "8.8.8.8"
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	// Windows has no mode bits; the state directory's access list protects it.
	if info, _ := os.Stat(p); runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	got, err := Load(p)
	if err != nil || got.IP != s.IP {
		t.Fatal(got, err)
	}
	unlock, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Lock(p); err == nil {
		other()
		t.Fatal("second writer acquired lock")
	}
	unlock()
	other, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	other()
	if err = os.WriteFile(p, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(p); err == nil {
		t.Fatal("corrupt state reset silently")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "broken" {
		t.Fatal("corrupt evidence overwritten")
	}
}
