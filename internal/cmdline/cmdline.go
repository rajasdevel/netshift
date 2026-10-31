// Package cmdline parses one command's options and positional arguments in
// any order and turns every problem into a usage error that names the
// command, so the caller can print it once and exit with status 2.
package cmdline

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// ErrUsage reports a command line that cannot run; netshift exits with
// status 2. Without more detail, it prints the full usage.
var ErrUsage = errors.New("usage")

// ErrGlobalAfterCommand marks a usage error for a global option, such as
// --config, given after COMMAND. cli reports it before loading a profile.
var ErrGlobalAfterCommand = errors.New("global option after the command")

// UsageError is a command line that cannot run. netshift prints the message
// and then the command's usage, both once, and exits with status 2. It
// matches ErrUsage, and its cause when set, with errors.Is.
type UsageError struct {
	Message string
	Usage   string // the command's usage; empty points to netshift help
	cause   error  // an optional, more specific sentinel
}

// Error returns the message alone; netshift prints the usage after it.
func (e *UsageError) Error() string { return e.Message }

// Unwrap returns ErrUsage and the cause, if any.
func (e *UsageError) Unwrap() []error {
	if e.cause != nil {
		return []error{ErrUsage, e.cause}
	}
	return []error{ErrUsage}
}

// globalOptions are the options that must come before COMMAND.
var globalOptions = []string{"config", "state", "log-file", "verbose", "version"}

// Line is one command's options and usage text.
type Line struct {
	*flag.FlagSet
	synopsis, summary string
}

// New returns a command line that reports errors only through its
// return values: the flag package prints nothing itself.
func New(name, synopsis, summary string) *Line {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard) // errors return to the caller, which prints them once
	f.Usage = func() {}
	return &Line{FlagSet: f, synopsis: synopsis, summary: summary}
}

// Help is the command's help text, with options written as --name.
func (c *Line) Help() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: netshift %s\n", c.synopsis)
	if c.summary != "" {
		fmt.Fprintf(&b, "\n%s\n", c.summary)
	}
	header := "\nOptions:\n"
	c.VisitAll(func(fl *flag.Flag) {
		b.WriteString(header)
		header = ""
		kind, text := flag.UnquoteUsage(fl)
		left := "--" + fl.Name
		if kind != "" {
			left += " " + kind
		}
		if !slices.Contains([]string{"", "false", "0", "[]"}, fl.DefValue) {
			text += " (default " + fl.DefValue + ")"
		}
		if len(left) > 20 {
			fmt.Fprintf(&b, "  %s\n  %-20s %s\n", left, "", text)
		} else {
			fmt.Fprintf(&b, "  %-20s %s\n", left, text)
		}
	})
	return b.String()
}

// Errorf returns a usage error that prints this command's usage.
func (c *Line) Errorf(format string, args ...any) error {
	return &UsageError{Message: c.Name() + ": " + fmt.Sprintf(format, args...), Usage: c.Help()}
}

// ParseArgs sets options and returns the positional arguments. Options may
// come before, between, or after positional arguments: Go's flag package
// stops at the first positional, so "run --apply NAME" or "test-event --ip IP
// ip_changed" would otherwise misparse. "--" ends options. -h returns
// flag.ErrHelp, and the caller prints usage; a global option such as --config
// is reported as belonging before COMMAND; any other problem is a usage error.
func (c *Line) ParseArgs(args []string) ([]string, error) {
	var options, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		options = append(options, arg)
		name := strings.TrimPrefix(arg[1:], "-")
		if strings.Contains(name, "=") {
			continue
		}
		fl := c.Lookup(name)
		if fl == nil || isBoolFlag(fl) {
			continue // flag.Parse reports unknown options
		}
		if i+1 == len(args) {
			return nil, c.Errorf("option --%s needs a value", name)
		}
		i++
		options = append(options, args[i])
	}
	err := c.Parse(append(append(options, "--"), positional...))
	if errors.Is(err, flag.ErrHelp) {
		return nil, err
	}
	if err != nil {
		if name, ok := strings.CutPrefix(err.Error(), "flag provided but not defined: -"); ok && slices.Contains(globalOptions, name) {
			return nil, &UsageError{Message: fmt.Sprintf("%s: global option --%s must come before COMMAND", c.Name(), name),
				Usage: c.Help(), cause: ErrGlobalAfterCommand}
		}
		return nil, c.Errorf("%s", Dashes(err.Error()))
	}
	return c.Args(), nil
}

// ParseNone parses a command line that takes options but no arguments.
func (c *Line) ParseNone(args []string) error {
	positional, err := c.ParseArgs(args)
	if err == nil && len(positional) != 0 {
		err = c.Errorf("unexpected arguments %q", positional)
	}
	return err
}

// isBoolFlag reports whether fl takes no value, as --apply does.
func isBoolFlag(fl *flag.Flag) bool {
	b, ok := fl.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// flagErrorName matches a flag package error up to the "-" before the option
// name. A quoted value (%q, so it holds no bare quote) may precede the name.
var flagErrorName = regexp.MustCompile(`^(?:flag provided but not defined: |flag needs an argument: |` +
	`invalid boolean value "(?:[^"\\]|\\.)*" for |invalid value "(?:[^"\\]|\\.)*" for flag )-`)

// Dashes rewrites the flag package's "-name" in an error as "--name", the
// spelling the usage text uses.
func Dashes(message string) string {
	if loc := flagErrorName.FindStringIndex(message); loc != nil {
		return message[:loc[1]] + "-" + message[loc[1]:]
	}
	return message
}
