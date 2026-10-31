package cmdline

import (
	"errors"
	"flag"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func testLine() (*Line, *bool, *string) {
	l := New("run", "--config FILE run NAME [--apply]", "Run one action.")
	apply := l.Bool("apply", false, "run the action")
	ip := l.String("ip", "", "simulated `IP`")
	return l, apply, ip
}

func TestParseArgsAcceptsOptionsAnywhere(t *testing.T) {
	for _, args := range [][]string{
		{"--apply", "--ip", "8.8.8.8", "hook"},
		{"hook", "--apply", "--ip=8.8.8.8"},
		{"--ip", "8.8.8.8", "hook", "-apply"},
	} {
		l, apply, ip := testLine()
		positional, err := l.ParseArgs(args)
		if err != nil || !*apply || *ip != "8.8.8.8" || !slices.Equal(positional, []string{"hook"}) {
			t.Errorf("%q: positional %q apply %t ip %q: %v", args, positional, *apply, *ip, err)
		}
	}
}

func TestParseArgsStopsAtDoubleDash(t *testing.T) {
	l, apply, _ := testLine()
	positional, err := l.ParseArgs([]string{"hook", "--", "--apply", "-x"})
	if err != nil || *apply || !slices.Equal(positional, []string{"hook", "--apply", "-x"}) {
		t.Fatalf("positional %q apply %t: %v", positional, *apply, err)
	}
}

func TestParseArgsErrors(t *testing.T) {
	for _, c := range []struct {
		args    []string
		message string
		global  bool
	}{
		{[]string{"hook", "--ip"}, "run: option --ip needs a value", false},
		{[]string{"--nope"}, "run: flag provided but not defined: --nope", false},
		{[]string{"hook", "--config", "x.json"}, "run: global option --config must come before COMMAND", true},
		{[]string{"--apply=maybe"}, `run: invalid boolean value "maybe" for --apply: parse error`, false},
	} {
		l, _, _ := testLine()
		_, err := l.ParseArgs(c.args)
		var bad *UsageError
		if !errors.As(err, &bad) || !errors.Is(err, ErrUsage) || bad.Message != c.message {
			t.Errorf("%q: %v, want usage error %q", c.args, err, c.message)
			continue
		}
		if errors.Is(err, ErrGlobalAfterCommand) != c.global {
			t.Errorf("%q: global-after-command is %t", c.args, !c.global)
		}
		if !strings.HasPrefix(bad.Usage, "Usage: netshift --config FILE run NAME") {
			t.Errorf("%q: usage %q", c.args, bad.Usage)
		}
	}
}

func TestParseArgsHelpPrintsNothing(t *testing.T) {
	l, _, _ := testLine()
	if _, err := l.ParseArgs([]string{"hook", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("got %v, want flag.ErrHelp", err)
	}
}

func TestParseNoneRejectsArguments(t *testing.T) {
	l, _, _ := testLine()
	if err := l.ParseNone([]string{"extra"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), `unexpected arguments ["extra"]`) {
		t.Fatal(err)
	}
	if err := l.ParseNone([]string{"--apply"}); err != nil {
		t.Fatal(err)
	}
}

func TestHelpListsOptionsWithDoubleDashes(t *testing.T) {
	l, _, _ := testLine()
	help := l.Help()
	for _, want := range []string{"Usage: netshift --config FILE run NAME [--apply]\n", "\nRun one action.\n", "--apply", "--ip IP"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
}

func TestDashes(t *testing.T) {
	for in, want := range map[string]string{
		"flag provided but not defined: -x":       "flag provided but not defined: --x",
		"flag needs an argument: -ip":             "flag needs an argument: --ip",
		`invalid value "a -b" for flag -limit: x`: `invalid value "a -b" for flag --limit: x`,
		"something else -x":                       "something else -x",
	} {
		if got := Dashes(in); got != want {
			t.Errorf("Dashes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuoteRoundTripsThroughSh(t *testing.T) {
	for in, want := range map[string]string{
		"/home/sam/work.local.json": "/home/sam/work.local.json",
		"/home/sam/my profile.json": "'/home/sam/my profile.json'",
		"/tmp/it's $(here).json":    `'/tmp/it'\''s $(here).json'`,
		"/tmp/a\"b\\c`d`.json":      "'/tmp/a\"b\\c`d`.json'",
		"":                          "''",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
		out, err := exec.CommandContext(t.Context(), "/bin/sh", "-c", "printf %s "+ShellQuote(in)).Output()
		if err != nil || string(out) != in {
			t.Errorf("sh read %s as %q: %v", ShellQuote(in), out, err)
		}
	}
}

// A command with several forms prints each on its own usage line, aligned.
func TestHelpPrintsEachForm(t *testing.T) {
	f := New("init", "init azure --output FILE\ninit command --output FILE", "Write a profile.")
	f.String("output", "", "new `FILE`")
	want := "Usage: netshift init azure --output FILE\n       netshift init command --output FILE\n\nWrite a profile.\n\nOptions:\n  --output FILE        new FILE\n"
	if got := f.Help(); got != want {
		t.Fatalf("help:\n%s\nwant:\n%s", got, want)
	}
	if f.Synopsis() != "init azure --output FILE\ninit command --output FILE" || f.Summary() != "Write a profile." {
		t.Fatalf("synopsis %q, summary %q", f.Synopsis(), f.Summary())
	}
}

// Options describe each option for completion: its value placeholder, or
// none for an option that takes no value.
func TestOptionsForCompletion(t *testing.T) {
	f := New("x", "x", "")
	f.Bool("apply", false, "allow `writes`")
	f.String("file", "", "read `FILE`")
	f.Int("lines", 5, "show lines")
	f.Func("ip", "an `IP`", func(string) error { return nil })
	want := []Option{{"apply", "", "allow writes"}, {"file", "FILE", "read FILE"}, {"ip", "IP", "an IP"}, {"lines", "int", "show lines"}}
	if got := f.Options(); !slices.Equal(got, want) {
		t.Fatalf("options %+v, want %+v", got, want)
	}
}

// FirstArgument finds the argument ParseArgs would, skipping option values,
// and checks nothing else.
func TestFirstArgumentSkipsOptionValues(t *testing.T) {
	f := New("init", "init", "")
	f.String("output", "", "`FILE`")
	f.Bool("apply", false, "")
	for want, args := range map[string][]string{
		"azure":   {"--output", "azure.json", "azure"},
		"command": {"--apply", "--output=x", "command", "extra"},
		"-x":      {"--", "-x"},
		"kind":    {"--bogus", "kind", "--output"},
		"":        {"--output", "x"},
	} {
		if got := f.FirstArgument(args); got != want {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
}
