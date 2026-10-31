package engine

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
)

// exampleProfile copies config/NAME from the repository into a temporary
// file and returns its path.
func exampleProfile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "config", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err = os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A state file first bound to the identity by watch must be written on the
// first poll, even a quiet one that changes nothing else.
func TestIdentityBindingSavedOnFirstQuietPoll(t *testing.T) {
	c, err := config.Load(exampleProfile(t, "azure.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := c.Actions["azure_allowlist"]
	a.Devices.LegacyIdentity = "sam@laptop"
	c.Actions["azure_allowlist"] = a
	c.Identity = "sam@laptop"
	path := filepath.Join(t.TempDir(), "state.json")
	unbound := `{"version":1,"ip":"8.8.8.8","connectivity":"online","actions":{"azure_allowlist":{}}}`
	if err = os.WriteFile(path, []byte(unbound), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Open(c, path, true, false, eventlog.Logger{Out: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if e.State.Identity != "sam@laptop" {
		t.Fatal("identity not bound")
	}
	// Online but unverified: no observation, event, or action state changes.
	if err = e.step(t.Context(), discovery.Observation{Online: true}, false, false); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load(path)
	if err != nil || saved.Identity != "sam@laptop" {
		t.Fatalf("binding not saved: %+v %v", saved, err)
	}
	// An already bound state stays quiet.
	if e, err = Open(c, path, true, false, eventlog.Logger{Out: io.Discard}); err != nil || e.pendingSave {
		t.Fatalf("bound state marked unsaved: %v", err)
	}
}
