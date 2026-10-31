package proc

import (
	"strings"
	"testing"
)

// Go and the C runtime read these arguments back literally.
func TestWindowsArg(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "": `""`, "two words": `"two words"`, `C:\dir\`: `C:\dir\`, `C:\my dir\`: `"C:\my dir\\"`,
		`say "hi"`: `"say \"hi\""`, `a\"b`: `"a\\\"b"`, "tab\tx": "\"tab\tx\"",
	} {
		if got := WindowsArg(in); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
	if got := quoteArg("plain"); got != `"plain"` {
		t.Errorf("quoteArg always quotes: %s", got)
	}
}

// Every argument is quoted for the C runtime behind a batch file, and the
// operators in it stay inside cmd.exe's quotes.
func TestBatchCommandLineQuotesEveryArgument(t *testing.T) {
	line, err := batchCommandLine(`C:\Windows\System32\cmd.exe`, `C:\Program Files\CLI2\wbin\az.cmd`,
		[]string{"network", "a b", "&calc", "(x)", "^", `dir\`, "", "ü", `{"ips":["8.8.8.8"],"id":"sam@host"}`, `say "hi"`})
	want := `"C:\Windows\System32\cmd.exe" /d /q /v:off /s /c ""C:\Program Files\CLI2\wbin\az.cmd" "network" "a b" "&calc" "(x)" "^" "dir\\" "" "ü" "{\"ips\":[\"8.8.8.8\"],\"id\":\"sam@host\"}" "say \"hi\"""`
	if err != nil || line != want {
		t.Fatalf("got  %s\nwant %s\n%v", line, want, err)
	}
}

// What cmd.exe expands, and operators that a " would leave outside its
// quotes, are refused; the error names the argument without repeating it.
func TestBatchCommandLineRefusesWhatCmdInterprets(t *testing.T) {
	for _, bad := range []string{"%PATH%", "50%", "!x!", "a\nb", "a\rb", "tab\there", "nul\x00", "\xff",
		`a"b&c`, `x"|y`, `{"a":"b(c"}`, `"^"^`} {
		_, err := batchCommandLine(`C:\cmd.exe`, `C:\az.cmd`, []string{"ok", bad})
		if err == nil || !strings.Contains(err.Error(), "argument 2") || strings.Contains(err.Error(), bad) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// An odd number of quotes in one argument exposes the next one.
	if _, err := batchCommandLine(`C:\cmd.exe`, `C:\az.cmd`, []string{`a"b`, "x&y"}); err == nil || !strings.Contains(err.Error(), "argument 2") {
		t.Errorf("exposed by an earlier argument: %v", err)
	}
	if _, err := batchCommandLine(`C:\cmd.exe`, `C:\100%\az.cmd`, nil); err == nil || !strings.Contains(err.Error(), "batch file path") {
		t.Errorf("script path: %v", err)
	}
}
