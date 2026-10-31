package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/service"
)

// Each script dispatches on exactly the commands of the command table and
// offers exactly each one's options, and the global options before COMMAND.
func TestCompletionScriptsCoverTheCommandTable(t *testing.T) {
	g, _ := globalCommandLine()
	want := map[string][]string{"": optionNamesOf(g.Options())}
	for _, c := range commands() {
		want[c.name] = optionNamesOf(c.line().Options())
	}
	// Each pattern finds one command's section of the script, or the global
	// one (an empty name); option finds the options in it.
	option := regexp.MustCompile(`--([a-z][a-z-]*)`)
	for shell, section := range map[string]*regexp.Regexp{
		"bash": regexp.MustCompile(`(?m)^\t(?:local|\t\t([a-z-]+)\)) (opts=.*)$`),
		"zsh":  regexp.MustCompile(`(?m)^\t(?:|\t\t\(([a-z-]+)\) )(opts=.*)$`),
		"fish": regexp.MustCompile(`(?m)^complete -c netshift -n '__netshift_at (?:""|([a-z-]+))' (-l .*)$`),
	} {
		got := map[string][]string{}
		for _, m := range section.FindAllStringSubmatch(completionScript(shell), -1) {
			if shell == "fish" {
				m[2] = "--" + strings.Fields(m[2])[1] // -l NAME ...
			} else if shell == "zsh" {
				m[2] = strings.Split(m[2], " valued=")[0] // descriptions may hold anything
			} else {
				m[2] = strings.Split(m[2], "' ")[0]
			}
			for _, o := range option.FindAllStringSubmatch(m[2], -1) {
				got[m[1]] = append(got[m[1]], o[1])
			}
			if _, ok := got[m[1]]; !ok {
				got[m[1]] = nil
			}
		}
		for name, options := range want {
			if _, ok := got[name]; !ok && (len(options) != 0 || shell != "fish") {
				t.Errorf("%s: no section for %q", shell, name)
			}
			if !slices.Equal(got[name], options) {
				t.Errorf("%s: %q offers %q, want %q", shell, name, got[name], options)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("%s: section for unknown command %q", shell, name)
			}
		}
	}
	for _, shell := range completionShells {
		script := completionScript(shell)
		for _, c := range commands() {
			for _, word := range c.choices {
				if !strings.Contains(script, word) {
					t.Errorf("%s: %s choice %s missing", shell, c.name, word)
				}
			}
		}
	}
}

func optionNamesOf(options []cmdline.Option) []string {
	var names []string
	for _, o := range options {
		names = append(names, o.Name)
	}
	return names
}

// The scripts embed command, option, and choice names unquoted in places
// (case patterns, fish switch arms), so each must be a plain word, and no
// description may hold a newline. A future choice computed at run time
// cannot then inject shell code.
func TestCompletionWordsAreSafe(t *testing.T) {
	word := regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	global, specs := completionSpecs()
	for _, s := range append(specs, global) {
		if s.name != "" && !word.MatchString(s.name) {
			t.Errorf("command %q is not a plain word", s.name)
		}
		if strings.ContainsAny(s.about, "\r\n") {
			t.Errorf("%s: description %q holds a newline", s.name, s.about)
		}
		for _, o := range s.options {
			if !word.MatchString(o.Name) || strings.ContainsAny(o.Usage, "\r\n") || strings.ContainsAny(o.Value, "\r\n") {
				t.Errorf("%s: option %+v is unsafe", s.name, o)
			}
		}
		for _, c := range s.choices {
			if !word.MatchString(c) {
				t.Errorf("%s: choice %q is not a plain word", s.name, c)
			}
		}
	}
}

func TestCompletionUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"completion"}, {"completion", "tcsh"}, {"completion", "bash", "zsh"}, {"completion", "--bogus", "bash"}} {
		out := captureOutput(t)
		err := cli(t.Context(), args)
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || strings.Count(stderr.String(), "Usage: netshift completion bash | zsh | fish") != 1 || out.Len() != 0 {
			t.Errorf("%q: %v\n%s", args, err, stderr.String())
		}
	}
}

// completionCase is a command line up to the cursor, whose last word is
// being completed, and the candidates every shell should offer for it.
type completionCase struct {
	line string
	want []string
}

func completionCases() []completionCase {
	var names []string
	for _, c := range commands() {
		names = append(names, c.name)
	}
	return []completionCase{
		{"netshift ", names},
		{"netshift --config x.json ser", []string{"service"}},
		{"netshift --verbose -- st", []string{"status"}},
		{"netshift --con", []string{"--config"}},
		{"netshift --log-file x.log --st", []string{"--state"}},
		{"netshift service ", service.Operations},
		{"netshift service install --", []string{"--apply", "--replace", "--start"}},
		{"netshift service install ", nil},
		{"netshift test-event --ip 8.8.8.8 ", testEvents},
		{"netshift test-event --apply ", testEvents},
		{"netshift help ", names},
		{"netshift help status ", nil},
		{"netshift init --output x.json ", initKinds},
		{"netshift completion ", completionShells},
		{"netshift devices --action allow ", engine.DeviceOperations},
		{"netshift run -- --a", nil},
		{"netshift history --limit ", nil},
		{"netshift bogus ", nil},
	}
}

// checkCompletions compares each case's candidates, as one line of output
// per case, in any order.
func checkCompletions(t *testing.T, shell string, cases []completionCase, output string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != len(cases) {
		t.Fatalf("%s: %d results for %d cases:\n%s", shell, len(lines), len(cases), output)
	}
	for i, tc := range cases {
		got := strings.Fields(lines[i])
		want := slices.Clone(tc.want)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: %q completes to %q, want %q", shell, tc.line, got, want)
		}
	}
}

func completionScriptFile(t *testing.T, shell, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(completionScript(shell)), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The bash script runs as bash calls it, under every bash on this machine,
// including macOS's bash 3.2, which lacks compopt.
func TestBashCompletion(t *testing.T) {
	var shells []string
	for _, name := range []string{"bash", "/bin/bash"} {
		if path, err := exec.LookPath(name); err == nil && !slices.Contains(shells, path) {
			shells = append(shells, path)
		}
	}
	if len(shells) == 0 {
		t.Skip("bash is not installed")
	}
	script := completionScriptFile(t, "bash", "netshift.bash")
	cases := append(completionCases(),
		// bash splits --name=value at "=".
		completionCase{"netshift --config = x.json st", []string{"status"}},
		// File values are left to complete -o default.
		completionCase{"netshift --config ", nil},
		completionCase{"netshift logs --file = ", nil},
	)
	var driver strings.Builder
	driver.WriteString(`. "$1"
c() { COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]} - 1)); COMPREPLY=(); _netshift; echo "${COMPREPLY[*]}"; }
`)
	for _, tc := range cases {
		driver.WriteString("c")
		for _, word := range strings.Split(tc.line, " ") {
			driver.WriteString(" " + singleQuote(word))
		}
		driver.WriteString("\n")
	}
	for _, bash := range shells {
		out, err := exec.CommandContext(t.Context(), bash, "--norc", "--noprofile", "-c", driver.String(), "bash", script).Output()
		if err != nil {
			t.Fatalf("%s: %v", bash, err)
		}
		checkCompletions(t, bash, cases, string(out))
	}
}

// zsh completion functions run only inside the line editor, so the script's
// own logic runs here with stand-ins for _describe, _files, and compset, and
// a real compinit must register it both sourced and from $fpath.
func TestZshCompletion(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	script := completionScriptFile(t, "zsh", "_netshift")
	if out, err := exec.CommandContext(t.Context(), zsh, "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v\n%s", err, out)
	}
	compinit := "autoload -Uz compinit && compinit -u -D"
	for _, register := range []string{
		compinit + " && source " + singleQuote(script),                            // the script calls compdef
		"fpath=(" + singleQuote(filepath.Dir(script)) + " $fpath) && " + compinit, // compinit reads #compdef
	} {
		out, err := exec.CommandContext(t.Context(), zsh, "-f", "-c", register+" && print -r -- $_comps[netshift]").Output()
		if err != nil || strings.TrimSpace(string(out)) != "_netshift" {
			t.Errorf("%s: not registered: %q %v", register, out, err)
		}
	}
	cases := append(completionCases(),
		completionCase{"netshift --config ", []string{"<files>"}},
		completionCase{"netshift logs --file=h", []string{"<files>"}},
		completionCase{"netshift logs --lines=", nil},
	)
	var driver strings.Builder
	driver.WriteString(`compdef() { : }
_describe() { local -a names; names=("${(@)${(@P)${@[-1]}}%%:*}"); reply+=(${(M)names:#${(b)PREFIX}*}); }
_files() { reply+=('<files>'); }
compset() { PREFIX=${PREFIX#*=}; }
. "$1"
c() { local -a reply; words=("$@"); CURRENT=$#words; PREFIX=$words[-1]; _netshift; print -r -- "${reply[*]}"; }
`)
	for _, tc := range cases {
		driver.WriteString("c")
		for _, word := range strings.Split(tc.line, " ") {
			driver.WriteString(" " + singleQuote(word))
		}
		driver.WriteString("\n")
	}
	out, err := exec.CommandContext(t.Context(), zsh, "-f", "-c", driver.String(), "zsh", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	checkCompletions(t, "zsh", cases, string(out))
}

// fish completes a command line non-interactively with complete -C.
func TestFishCompletion(t *testing.T) {
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("fish is not installed")
	}
	script := completionScriptFile(t, "fish", "netshift.fish")
	if out, err := exec.CommandContext(t.Context(), fish, "--no-config", "--no-execute", script).CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v\n%s", err, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "home.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	cases := append(completionCases(),
		completionCase{"netshift --config ", []string{"home.json"}},
		completionCase{"netshift logs --file=h", []string{"--file=home.json"}},
	)
	var driver strings.Builder
	driver.WriteString("source " + fishQuote(script) + "\n")
	for _, tc := range cases {
		driver.WriteString("set -l r (complete -C " + fishQuote(tc.line) + " | string split -f1 \\t); echo \"$r\"\n")
	}
	cmd := exec.CommandContext(t.Context(), fish, "--no-config", "-c", driver.String())
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	checkCompletions(t, "fish", cases, string(out))
}
