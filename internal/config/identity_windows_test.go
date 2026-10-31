//go:build windows

package config

import "testing"

// Windows reports DOMAIN\user; the identity uses the case-folded user.
func TestAccountName(t *testing.T) {
	for in, want := range map[string]string{`DESKTOP-1\Sam`: "sam", `CORP\sam.smith`: "sam.smith", "runner": "runner"} {
		if got := accountName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
