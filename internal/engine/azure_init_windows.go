//go:build windows

package engine

import (
	"fmt"
	"io"
	"strings"
)

// printCreated reports a new profile, with the next command quoted for
// PowerShell, the shell Windows users type commands in.
func printCreated(out io.Writer, path string, targets int, identity string) {
	fmt.Fprintf(out, "Created %s for %d selected rules/servers. Seed IPs belong to %s.\nReview the profile, then preview: netshift --config %s devices enroll\nAzure was only read; enrollment requires --apply.\n", path, targets, identity, powershellQuote(path))
}

// powershellQuote quotes s for PowerShell. Plain words, Windows paths
// included, stay readable; anything else is a single-quoted string, which
// expands nothing, with each quote doubled. PowerShell also reads the
// typographic single quotes as quotes.
func powershellQuote(s string) string {
	plain := s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(`_-./\:`, r))
	}) < 0
	if plain {
		return s
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		if strings.ContainsRune("'\u2018\u2019\u201A\u201B", r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}
