package proc

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Windows runs a .cmd or .bat file only through cmd.exe, which reads the
// command line with its own rules rather than the C runtime's that Go's
// argument escaping follows: it expands %VAR% even inside quotes, every "
// toggles its quoting (a backslash does not escape it), and outside quotes
// & | < > ( ) and ^ are operators. A batch file's %* then hands the same
// text to the next program (az.cmd passes it to python.exe), which reads it
// with the C runtime's rules, after cmd.exe has parsed it once more.
// Escaping that both readers agree on does not exist for every string (the
// "BatBadBut" bugs), so batchCommandLine passes only arguments that mean the
// same to both, and refuses the rest:
//
//   - every argument is quoted as the C runtime reads it back (WindowsArg,
//     always quoted), so the program receives exactly the argument;
//   - % and !, which cmd.exe expands even inside quotes, and control
//     characters, which end the command, are refused anywhere;
//   - cmd.exe's quoting is traced over the whole command line, and an
//     argument is refused if any operator character in it would end up
//     outside quotes. Without ^ escapes, each parse of the text sees the
//     same quoting, so this holds for the second parse too.
//
// A JSON value such as {"ips":["8.8.8.8"]} passes; a " that would expose a
// later & is refused. cmd.exe runs with /d (no AutoRun commands from the
// registry), /q (no command echo in the output), /v:off (no delayed
// expansion), and /s /c, which strips exactly the outer pair of quotes and
// runs the rest.

// cmdOperators are the characters cmd.exe interprets outside quotes.
const cmdOperators = "&|<>()^"

// batchCommandLine returns the cmd.exe command line that runs the batch file
// script with args, each received literally, or an error naming the first
// argument that cannot be passed safely. cmdExe is cmd.exe's absolute path.
func batchCommandLine(cmdExe, script string, args []string) (string, error) {
	words := append([]string{script}, args...)
	var line strings.Builder
	quoted := false // cmd.exe's quoting, from the start of the line
	for i, word := range words {
		what := "the batch file path"
		if i > 0 {
			what = fmt.Sprintf("argument %d", i)
		}
		if err := batchSafe(word); err != nil {
			return "", fmt.Errorf("cannot run %s safely: %s %v", script, what, err)
		}
		q := quoteArg(word)
		for _, r := range q {
			if r == '"' {
				quoted = !quoted
			} else if !quoted && strings.ContainsRune(cmdOperators, r) {
				return "", fmt.Errorf("cannot run %s safely: %s has %q outside cmd.exe's quotes", script, what, r)
			}
		}
		if i > 0 {
			line.WriteByte(' ')
		}
		line.WriteString(q)
	}
	return `"` + cmdExe + `" /d /q /v:off /s /c "` + line.String() + `"`, nil
}

// batchSafe refuses what cmd.exe expands or stops at wherever it appears.
// The error does not repeat the word, which may be long.
func batchSafe(s string) error {
	for i, r := range s {
		switch {
		case r == utf8.RuneError:
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return fmt.Errorf("is not valid UTF-8")
			}
		case r == '%' || r == '!':
			return fmt.Errorf("contains %q, which cmd.exe expands", r)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("contains control character U+%04X", r)
		}
	}
	return nil
}

// WindowsArg quotes one argument of a Windows command line the way the C
// runtime, and Go's own command-line parser, read it back, as
// syscall.EscapeArg does on Windows: only when it needs quotes.
func WindowsArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	return quoteArg(s)
}

// quoteArg quotes s for the C runtime, always: inside the quotes, a " is
// escaped with a backslash, and backslashes before a " or the closing quote
// are doubled.
func quoteArg(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := range len(s) {
		switch c := s[i]; c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*slashes+1) + `"`)
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			b.WriteByte(c)
			slashes = 0
		}
	}
	b.WriteString(strings.Repeat(`\`, 2*slashes) + `"`)
	return b.String()
}
