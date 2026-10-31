package engine

import (
	"slices"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
)

// FuzzParseDevice feeds arbitrary registry tag values, which anyone with tag
// write access can set, to the device record parser. An accepted record must
// re-encode into a value that parses back to the same identity and revision
// with no address it did not have.
func FuzzParseDevice(f *testing.F) {
	for _, s := range []string{
		`{"v":2,"id":"sam@laptop","r":1,"ips":["8.8.8.8"]}`,
		`{"v":2,"id":"sam@laptop","r":3,"ips":["8.8.8.8","1.1.1.1"],"retired":true}`,
		`{"v":2,"id":"Sam@Laptop","r":1,"ips":["8.8.8.8"]}`,
		`{"v":2,"id":"sam@laptop","r":1,"ips":["8.8.8.8"]}{}`,
		`{"v":1,"ips":["8.8.8.8"]}`,
		``,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		d, err := parseDevice(raw)
		if err != nil {
			return
		}
		value, err := encodeDevice(d, 10)
		if err != nil {
			return // a record another writer stored may not fit a marker budget
		}
		back, err := parseDevice(value)
		if err != nil {
			t.Fatalf("encoded record %q is rejected: %v", value, err)
		}
		if back.Identity != d.Identity || back.Revision != d.Revision || back.Retired != d.Retired {
			t.Fatalf("round trip changed %+v into %+v", d, back)
		}
		for _, ip := range back.IPs {
			if !slices.Contains(d.IPs, ip) {
				t.Fatalf("round trip added %s", ip)
			}
		}
	})
}

// FuzzHistoryTag feeds arbitrary shared-history tag values to their parser.
// An accepted history lists 1 to 10 unique canonical public IPv4 addresses.
func FuzzHistoryTag(f *testing.F) {
	for _, s := range []string{`{"v":1,"ips":["8.8.8.8"]}`, `{"v":1,"ips":["8.8.8.8","8.8.8.8"]}`, `{"v":2,"ips":[]}`, `{"v":1,"ips":["8.8.8.8"],"x":1}`, ``} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _, history, err := historyTag(map[string]string{"netshift.fuzz.ip-history": raw}, "netshift.fuzz.ip-history")
		if err != nil {
			return
		}
		if len(history.IPs) == 0 || len(history.IPs) > 10 {
			t.Fatalf("accepted %d addresses", len(history.IPs))
		}
		seen := map[string]bool{}
		for _, ip := range history.IPs {
			if v, err := config.PublicIPv4(ip); err != nil || v != ip || seen[ip] {
				t.Fatalf("accepted address %q", ip)
			}
			seen[ip] = true
		}
	})
}
