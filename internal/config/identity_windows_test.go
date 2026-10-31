//go:build windows

package config

import (
	"os/user"
	"testing"
)

// A local account is user@host; a domain account is domain.user@host, so the
// two never collide.
func TestAccountNameOn(t *testing.T) {
	for _, tc := range []struct{ username, computer, want string }{
		{`HOST\Sam`, "HOST", "sam"},
		{`host\sam`, "HOST", "sam"},
		{`CORP\Sam.Smith`, "HOST", "corp.sam.smith"},
		{`CORP\sam`, "HOST", "corp.sam"},
		{"runner", "HOST", "runner"},
	} {
		if got := accountNameOn(tc.username, tc.computer); got != tc.want {
			t.Errorf("%q on %s: %q, want %q", tc.username, tc.computer, got, tc.want)
		}
	}
	local, err := CanonicalIdentity(accountNameOn(`HOST\sam`, "HOST") + "@host")
	domain, err2 := CanonicalIdentity(accountNameOn(`CORP\sam`, "HOST") + "@host")
	if err != nil || err2 != nil || local == domain || domain != "corp.sam@host" {
		t.Fatalf("%q %v; %q %v", local, err, domain, err2)
	}
}

// This machine's own account resolves to a canonical identity.
func TestAccountNameOfThisAccount(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	name := accountName(u.Username)
	if _, err := CanonicalIdentity(name + "@host"); err != nil {
		t.Fatalf("%s -> %q: %v", u.Username, name, err)
	}
}
