package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse checks that no input panics the profile parser, and that every
// accepted profile survives the round trip that init, map, and service
// install use: written with JSON and read back, it is the same profile.
func FuzzParse(f *testing.F) {
	for _, pattern := range []string{"../../config/*.json", "../../recipes/*.json"} {
		paths, _ := filepath.Glob(pattern)
		for _, path := range paths {
			if data, err := os.ReadFile(path); err == nil {
				f.Add(data)
			}
		}
	}
	f.Add([]byte(`{"version":1,"profile":"x","actions":{"a":{"type":"command","command":["/bin/true"]}}}`))
	f.Add([]byte(`{"version":1,"profile":"x","Profile":"y","actions":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		out, err := JSON(c)
		if err != nil {
			t.Fatalf("accepted profile does not encode: %v", err)
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("encoded profile is rejected: %v\n%s", err, out)
		}
		if Fingerprint(again) != Fingerprint(c) {
			t.Fatalf("round trip changed the profile:\n%s", out)
		}
	})
}

// FuzzPublicIPv4 checks that an accepted address is canonical, global, and
// accepted again unchanged.
func FuzzPublicIPv4(f *testing.F) {
	for _, s := range []string{"8.8.8.8", " 1.1.1.1\n", "10.0.0.1", "203.0.113.7", "::1", "1.2.3", "08.8.8.8", "8.8.8.8/32", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ip, err := PublicIPv4(s)
		if err != nil {
			return
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr.String() != ip {
			t.Fatalf("PublicIPv4(%q) = %q, not a canonical global IPv4", s, ip)
		}
		if again, err := PublicIPv4(ip); err != nil || again != ip {
			t.Fatalf("PublicIPv4(%q) = %q, %v; want it unchanged", ip, again, err)
		}
	})
}
