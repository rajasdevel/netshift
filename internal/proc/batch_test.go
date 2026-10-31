package proc

import (
	"strings"
	"testing"
)

// Every argument is quoted; backslashes before a closing quote are doubled
// so the C runtime behind a batch file reads them literally.
func TestBatchCommandLineQuotesEveryArgument(t *testing.T) {
	line, err := batchCommandLine(`C:\Windows\System32\cmd.exe`, `C:\Program Files\CLI2\wbin\az.cmd`,
		[]string{"network", "a b", "&calc", "(x)", "^", `dir\`, `dir\\`, "", "ü"})
	want := `"C:\Windows\System32\cmd.exe" /d /q /v:off /s /c ""C:\Program Files\CLI2\wbin\az.cmd" "network" "a b" "&calc" "(x)" "^" "dir\\" "dir\\\\" "" "ü""`
	if err != nil || line != want {
		t.Fatalf("got  %s\nwant %s\n%v", line, want, err)
	}
}

// Characters cmd.exe interprets even inside quotes are refused, and the
// error names the argument's position without repeating it.
func TestBatchCommandLineRefusesWhatCmdInterprets(t *testing.T) {
	for _, bad := range []string{`say "hi"`, "%PATH%", "50%", "!x!", "a\nb", "a\rb", "tab\there", "nul\x00", "\xff"} {
		_, err := batchCommandLine(`C:\cmd.exe`, `C:\az.cmd`, []string{"ok", bad})
		if err == nil || !strings.Contains(err.Error(), "argument 2") || strings.Contains(err.Error(), bad) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := batchCommandLine(`C:\cmd.exe`, `C:\100%\az.cmd`, nil); err == nil || !strings.Contains(err.Error(), "batch file path") {
		t.Errorf("script path: %v", err)
	}
}
