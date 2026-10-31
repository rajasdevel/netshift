package proc

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Windows runs a .cmd or .bat file only through cmd.exe, which reads the
// command line with its own rules rather than the C runtime's that Go's
// argument escaping follows: it expands %VAR% even inside quotes, a "
// toggles its quoting, and an unquoted &, |, <, >, ( or ) ends the
// command. A batch file's %* then hands the same text to the next program
// (az.cmd passes it to python.exe), which reads it with C runtime rules.
// Escaping that both readers agree on does not exist for every string (the
// "BatBadBut" bugs), so batchCommandLine allows only arguments whose meaning
// is the same for both, and refuses the rest:
//
//   - every argument is wrapped in double quotes, inside which cmd.exe
//     treats & | < > ( ) ^ and spaces as plain text;
//   - a " could end that quoting, so it is refused;
//   - % is expanded even inside quotes, and ! is with delayed expansion,
//     so both are refused;
//   - line breaks end the command, so control characters are refused;
//   - backslashes before the closing quote are doubled, so the C runtime
//     does not read the last one as escaping it.
//
// cmd.exe runs with /d (no AutoRun commands from the registry), /q (no
// command echo in the output), /v:off (no delayed expansion), and /s /c,
// which strips exactly the outer pair of quotes and runs the rest.

// batchCommandLine returns the cmd.exe command line that runs the batch file
// script with args, each received literally, or an error naming the first
// argument that cannot be passed safely. cmdExe is cmd.exe's absolute path.
func batchCommandLine(cmdExe, script string, args []string) (string, error) {
	var b strings.Builder
	b.WriteString(`"` + cmdExe + `" /d /q /v:off /s /c "`)
	for i, arg := range append([]string{script}, args...) {
		quoted, err := batchQuote(arg)
		if err != nil {
			what := "the batch file path"
			if i > 0 {
				what = fmt.Sprintf("argument %d", i)
			}
			return "", fmt.Errorf("cannot run %s safely: %s %v", script, what, err)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quoted)
	}
	b.WriteByte('"')
	return b.String(), nil
}

// batchQuote quotes one word of a batch file command line (see
// batchCommandLine). The error does not repeat the word, which may be long.
func batchQuote(s string) (string, error) {
	for i, r := range s {
		switch {
		case r == utf8.RuneError:
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return "", fmt.Errorf("is not valid UTF-8")
			}
		case r == '"' || r == '%' || r == '!':
			return "", fmt.Errorf("contains %q, which cmd.exe would interpret", r)
		case r < 0x20 || r == 0x7f:
			return "", fmt.Errorf("contains control character U+%04X", r)
		}
	}
	trailing := len(s) - len(strings.TrimRight(s, `\`))
	return `"` + s + strings.Repeat(`\`, trailing) + `"`, nil
}
