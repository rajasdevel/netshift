package cmdline

import (
	"errors"
	"flag"
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
