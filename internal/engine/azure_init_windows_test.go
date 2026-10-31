//go:build windows

package engine

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/rajasdevel/netshift/internal/proc"
)

// On Windows the command NetShift prints is for PowerShell.
func TestInitPrintsPowerShellSafeCommand(t *testing.T) {
	values := []string{`C:\Users\sam\work.local.json`, `C:\Users\sam\my profile.json`, `C:\it's $(here) $env:PATH.json`,
		"C:\\tmp\\a\"b`c;d&e.json", "C:\\it’s.json", ""}
	var printed strings.Builder
	printCreated(&printed, `C:\my dir\it's.json`, 2, "sam@host")
	if !strings.Contains(printed.String(), `netshift --config 'C:\my dir\it''s.json' devices enroll`) {
		t.Fatalf("not quoted for PowerShell: %s", printed.String())
	}
	for _, in := range values[:2] {
		if got := powershellQuote(in); in == values[0] && got != in || in == values[1] && got != "'"+in+"'" {
			t.Errorf("powershellQuote(%q) = %s", in, got)
		}
	}
	// One PowerShell prints each value as it reads it back, one per line,
	// passed as a command argument, as a user types it.
	var script strings.Builder
	script.WriteString("[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n")
	for _, in := range values {
		script.WriteString("& { [Console]::Out.Write($args[0] + [char]10) } " + powershellQuote(in) + "\n")
	}
	units := utf16.Encode([]rune(script.String()))
	encoded := make([]byte, 0, 2*len(units))
	for _, u := range units {
		encoded = append(encoded, byte(u), byte(u>>8))
	}
	out, err := (proc.Exec{}).Run(t.Context(), "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}, nil)
	if err != nil || string(out) != strings.Join(values, "\n")+"\n" {
		t.Fatalf("PowerShell read %q: %v", out, err)
	}
}
