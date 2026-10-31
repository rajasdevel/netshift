// Package cli implements the netshift command line: the global options, the
// command table, help, and the handlers for commands that every profile has.
// The Azure commands (init azure, map, devices) live with the Azure action in
// package engine; cli parses their global options and calls them.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
	"github.com/rajasdevel/netshift/internal/version"
)

// runtimeOutput receives command output. logOutput, when set by --log-file,
// receives the engine's JSON event log instead of runtimeOutput, and also
// the plain-text "netshift: ..." line that exitStatus writes for a failure.
var (
	runtimeOutput io.Writer = os.Stdout
	logOutput     io.Writer
)

// eventLog returns the logger for the engine's JSON event log.
func eventLog() eventlog.Logger {
	if logOutput != nil {
		return eventlog.Logger{Out: logOutput}
	}
	return eventlog.Logger{Out: runtimeOutput}
}

// usage is the overview that help and -h print. Each command's own usage
// comes from its cmdline.Line.
const usage = `NetShift runs your actions when your public IP or connectivity changes.

Usage:
  netshift --config FILE [global options] COMMAND [options]
  netshift init azure [options]
  netshift help [COMMAND] | version

Global options (before COMMAND):
  --config FILE     Profile (JSON) to use. Required except for init.
  --state FILE      State file. Default: the native user state directory.
  --log-file FILE   Write the event log to FILE (1 MiB plus one backup).
  --verbose         Also log targets that were verified unchanged.
  --version         Print the version.

Commands:
  validate          Check the profile, without network access.
  once [--apply | --dry-run]
                    Confirm the current IPv4 and process actions once.
  watch [--apply | --dry-run]
                    Monitor connectivity and IP changes until stopped.
  run NAME [--apply | --dry-run]
                    Run one named action with the confirmed current IP.
  test-event EVENT [--ip IP] [--previous-ip IP] [--value V] [--previous-value V]
                    [--action NAME] [--apply]
                    Preview an event; --apply runs command hooks, never Azure.
  status [--json]   Show saved observations and action/retry state.
  doctor [--azure] [--checks] [--json]
                    Diagnose this profile without running actions.
  logs [--follow] [--lines N] [--json] [--file FILE]
                    Read this profile's event log.
  history [--limit N] [--target ID]
                    Show the persistent rule/IP audit history.
  service print | install [--start] [--replace] | start | stop | status
        | uninstall [--apply] [--replace]
                    Manage only this profile's native user service.
  identity          Show this profile's user@host identity.
  devices [--action NAME] [--apply] list | enroll | retire USER@HOST | activate
                    List, enroll, retire, or reactivate Azure device
                    identities. --apply allows the cloud writes.
  map [options]     Inventory NSGs and map exact known IPs (read-only).
  init azure [options]
                    Generate a profile from selected existing Azure rules (read-only).

Options may come before or after a command's arguments; "--" ends options.
Without --apply, commands only preview (--dry-run says so explicitly).
Installed services run watch --apply.
Run "netshift COMMAND -h" for a command's options.
Exit status: 0 on success, 1 on failure, 2 for an invalid command line.
`

// maxStandardError bounds standard error when it is a regular file: the
// macOS service's PROFILE.stderr.log, which launchd appends to on every
// relaunch and nothing rotates.
const maxStandardError = 1 << 20

// Main runs one command line and exits with its status.
func Main() {
	boundStandardError(os.Stderr, maxStandardError)
	ctx, stop := signalContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	err := cli(ctx, os.Args[1:])
	stop()
	os.Exit(exitStatus(err, os.Stderr))
}

// boundStandardError empties f at start when it is a regular file larger
// than limit. launchd relaunches a failing watcher every 10 seconds, and each
// start appends its error, so a persistent failure would otherwise grow the
// file without bound. A terminal or pipe is left alone.
func boundStandardError(f *os.File, limit int64) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= limit {
		return
	}
	if f.Truncate(0) != nil {
		return
	}
	// launchd opens the file for appending; rewind in case another opener did not.
	_, _ = f.Seek(0, io.SeekStart)
	fmt.Fprintf(f, "netshift: standard error exceeded %d bytes; earlier output was discarded\n", limit)
}

// signalContext is canceled by the first of sigs. It then restores default
// signal handling, so a second Ctrl-C ends a stuck shutdown immediately.
func signalContext(parent context.Context, sigs ...os.Signal) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(parent, sigs...)
	context.AfterFunc(ctx, stop)
	return ctx, stop
}

// exitStatus reports err on stderr and returns the process exit status:
// 0 for success or -h, 2 for an invalid command line, and 1 otherwise.
func exitStatus(err error, stderr io.Writer) int {
	var bad *cmdline.UsageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &bad):
		fmt.Fprintln(stderr, "netshift:", bad.Message)
		if bad.Usage == "" {
			fmt.Fprintln(stderr, `Run "netshift help" for usage.`)
		} else {
			fmt.Fprint(stderr, "\n", bad.Usage)
		}
		return 2
	case errors.Is(err, cmdline.ErrUsage):
		fmt.Fprint(stderr, usage)
		return 2
	}
	fmt.Fprintln(stderr, "netshift:", err)
	if logOutput != nil {
		// Keep the reason a service stopped in the event log that logs reads.
		fmt.Fprintln(logOutput, "netshift:", err)
	}
	return 1
}

// invocation is what the global options resolved to for one command.
type invocation struct {
	config     config.Config // the loaded profile; zero for commands without one
	configPath string        // absolute profile path
	statePath  string        // absolute state path
	verbose    bool
}

// command is one entry of the command table.
type command struct {
	name string
	// line returns the command's options and usage, without a profile.
	line func() *cmdline.Line
	// profile commands need --config; cli loads it and resolves --state.
	profile bool
	// refusesProfile commands reject --config and --state.
	refusesProfile bool
	// identity commands resolve the user@host identity before parsing their
	// arguments. once, watch, and run resolve it after parsing instead.
	identity bool
	run      func(ctx context.Context, in invocation, args []string) error
}

// commands returns the command table, which drives dispatch, help COMMAND,
// and identity resolution. A new command needs one entry here and a line in
// the usage text.
func commands() []command {
	table := []command{
		{name: "help", line: helpCommandLine,
			run: func(_ context.Context, _ invocation, args []string) error { return handleHelp(args) }},
		{name: "version", line: versionCommandLine,
			run: func(_ context.Context, _ invocation, args []string) error { return handleVersion(args) }},
		{name: "init", line: lineOf(engine.InitCommandLine), refusesProfile: true,
			run: func(ctx context.Context, _ invocation, args []string) error {
				return engine.HandleInit(ctx, args, proc.Exec{}, runtimeOutput)
			}},
		{name: "validate", line: validateCommandLine, profile: true,
			run: func(_ context.Context, in invocation, args []string) error { return handleValidate(in.config, args) }},
		{name: "identity", line: identityCommandLine, profile: true,
			run: func(_ context.Context, in invocation, args []string) error { return handleIdentity(in.config, args) }},
		{name: "test-event", line: lineOf(testEventCommandLine), profile: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleTestEvent(ctx, in.config, args, proc.Exec{})
			}},
		{name: "status", line: lineOf(statusCommandLine), profile: true,
			run: func(_ context.Context, in invocation, args []string) error {
				return handleStatus(in.config, in.statePath, args)
			}},
		{name: "doctor", line: lineOf(doctorCommandLine), profile: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleDoctor(ctx, in.config, in.configPath, in.statePath, args, proc.Exec{}, discovery.New(in.config.Monitor))
			}},
		{name: "logs", line: lineOf(logsCommandLine), profile: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleLogs(ctx, in.config, in.statePath, args)
			}},
		{name: "history", line: lineOf(historyCommandLine), profile: true,
			run: func(_ context.Context, in invocation, args []string) error { return handleHistory(in.statePath, args) }},
		{name: "service", line: lineOf(serviceCommandLine), profile: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleService(ctx, in.config, in.configPath, in.statePath, args)
			}},
		{name: "devices", line: func() *cmdline.Line { return engine.DevicesCommandLine(new(engine.DevicesOptions)) }, profile: true, identity: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				return engine.HandleDevices(ctx, in.config, in.statePath, args, runtimeOutput, eventLog())
			}},
		{name: "map", line: func() *cmdline.Line { return engine.MapCommandLine(new(engine.MapOptions)) }, profile: true, identity: true,
			run: func(ctx context.Context, in invocation, args []string) error {
				// A subscription-wide NSG listing can exceed the default 1 MiB limit.
				return engine.HandleMap(ctx, in.config, in.statePath, args, proc.Exec{MaxOutput: 64 << 20}, runtimeOutput)
			}},
	}
	for _, name := range []string{"once", "watch", "run"} {
		table = append(table, command{name: name, profile: true,
			line: func() *cmdline.Line { f, _ := runCommandLine(name); return f },
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleRun(ctx, in.config, in.statePath, name, args, in.verbose)
			}})
	}
	return table
}

// lineOf adapts a command-line constructor that also returns options.
func lineOf[T any](build func() (*cmdline.Line, T)) func() *cmdline.Line {
	return func() *cmdline.Line { f, _ := build(); return f }
}

// findCommand returns the table entry for name.
func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// cli parses the global options, then loads the profile and resolves the
// state file for the commands that need them, and runs the command.
func cli(ctx context.Context, args []string) error {
	logOutput = nil
	f := flag.NewFlagSet("netshift", flag.ContinueOnError)
	f.SetOutput(io.Discard) // exitStatus prints the error once
	f.Usage = func() {}
	configPath := f.String("config", "", "profile (JSON) to use")
	statePath := f.String("state", "", "state file (defaults to the native user state directory)")
	verbose := f.Bool("verbose", false, "also log targets that were verified unchanged")
	logFile := f.String("log-file", "", "write the event log to this file (1 MiB plus one backup)")
	showVersion := f.Bool("version", false, "print the version")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(runtimeOutput, usage)
			return err
		}
		return &cmdline.UsageError{Message: cmdline.Dashes(err.Error())}
	}
	if *showVersion {
		fmt.Fprintln(runtimeOutput, version.Number)
		return nil
	}
	if f.NArg() == 0 {
		return cmdline.ErrUsage
	}
	name, rest := f.Arg(0), f.Args()[1:]
	cmd, ok := findCommand(name)
	if !ok {
		return &cmdline.UsageError{Message: fmt.Sprintf("unknown command %q", name)}
	}
	line := cmd.line()
	// Answer -h, and a global option placed after the command, before
	// loading a profile, so help works without --config. Handlers parse
	// their arguments again and report any other problem.
	if _, err := line.ParseArgs(rest); errors.Is(err, flag.ErrHelp) || errors.Is(err, cmdline.ErrGlobalAfterCommand) {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(runtimeOutput, line.Help())
		}
		return err
	}
	if cmd.refusesProfile && (*configPath != "" || *statePath != "") {
		return &cmdline.UsageError{Message: name + " uses --output rather than --config/--state"}
	}
	in := invocation{verbose: *verbose}
	if !cmd.profile {
		return cmd.run(ctx, in, rest)
	}
	if *configPath == "" {
		return &cmdline.UsageError{Message: "--config FILE is required", Usage: line.Help()}
	}
	var err error
	if in.configPath, err = filepath.Abs(*configPath); err != nil {
		return err
	}
	if in.config, err = config.Load(in.configPath); err != nil {
		return err
	}
	if *statePath == "" {
		in.statePath, err = store.DefaultPath(in.config.Profile)
	} else {
		in.statePath, err = filepath.Abs(*statePath)
	}
	if err != nil {
		return err
	}
	for _, p := range []string{in.statePath, store.HistoryPath(in.statePath), in.statePath + ".lock"} {
		if fsx.SameFile(p, in.configPath) {
			return errors.New("state, history, and lock files must not be the profile")
		}
	}
	if *logFile != "" {
		path, err := filepath.Abs(*logFile)
		if err != nil {
			return err
		}
		if err = checkLogPath(path, in.configPath, in.statePath); err != nil {
			return err
		}
		logOutput = &eventlog.RotatingWriter{Path: path, MaxBytes: 1 << 20}
	}
	if cmd.identity {
		if in.config, err = config.WithIdentity(in.config); err != nil {
			return err
		}
	}
	return cmd.run(ctx, in, rest)
}

// checkLogPath refuses an event log, or its rotated backup, that is the
// profile or a state, history, or lock file: the log would append to it, and
// rotation would rename it away. The comparison covers files that do not
// exist yet (by cleaned path, ignoring case for case-insensitive volumes)
// and links to existing ones.
func checkLogPath(log, config, state string) error {
	protected := []string{config, state, store.HistoryPath(state), state + ".lock"}
	for _, l := range []string{log, log + ".1"} {
		for _, p := range protected {
			if strings.EqualFold(filepath.Clean(l), filepath.Clean(p)) || fsx.SameFile(l, p) {
				return errors.New("--log-file and its .1 backup must not be the profile or its state, history, or lock file")
			}
		}
	}
	return nil
}

// helpCommandLine describes help.
func helpCommandLine() *cmdline.Line {
	return cmdline.New("help", "help [COMMAND]", "Print the overview, or one command's usage.")
}

// handleHelp prints the overview, or one command's usage for help COMMAND.
func handleHelp(args []string) error {
	f := helpCommandLine()
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	switch {
	case len(positional) == 0:
		fmt.Fprint(runtimeOutput, usage)
		return nil
	case len(positional) > 1:
		return f.Errorf("unexpected arguments %q", positional[1:])
	}
	cmd, ok := findCommand(positional[0])
	if !ok {
		return &cmdline.UsageError{Message: fmt.Sprintf("help: unknown command %q", positional[0])}
	}
	fmt.Fprint(runtimeOutput, cmd.line().Help())
	return nil
}

// versionCommandLine describes version.
func versionCommandLine() *cmdline.Line {
	return cmdline.New("version", "version", "Print the version.")
}

// handleVersion prints the version.
func handleVersion(args []string) error {
	if err := versionCommandLine().ParseNone(args); err != nil {
		return err
	}
	fmt.Fprintln(runtimeOutput, version.Number)
	return nil
}

// validateCommandLine describes validate.
func validateCommandLine() *cmdline.Line {
	return cmdline.New("validate", "--config FILE validate", "Check the profile, without network access.")
}

// handleValidate reports a profile that config.Load already validated.
func handleValidate(c config.Config, args []string) error {
	if err := validateCommandLine().ParseNone(args); err != nil {
		return err
	}
	fmt.Fprintf(runtimeOutput, "Valid profile %q with actions: %s.\n", c.Profile, strings.Join(config.ActionNames(c), ", "))
	return nil
}

// identityCommandLine describes identity.
func identityCommandLine() *cmdline.Line {
	return cmdline.New("identity", "--config FILE identity", "Show this profile's user@host identity.")
}

// handleIdentity prints the profile's user@host identity, resolving it even
// for a profile without device actions.
func handleIdentity(c config.Config, args []string) error {
	if err := identityCommandLine().ParseNone(args); err != nil {
		return err
	}
	id, err := config.IdentityOf(c.Identity)
	if err != nil {
		return err
	}
	fmt.Fprintln(runtimeOutput, id)
	return nil
}

// historyOptions are the history command's options.
type historyOptions struct {
	limit  int
	target string
}

// historyCommandLine describes history.
func historyCommandLine() (*cmdline.Line, *historyOptions) {
	f := cmdline.New("history", "--config FILE history [--limit N] [--target ID]", "Show the persistent rule/IP audit history.")
	var o historyOptions
	f.IntVar(&o.limit, "limit", 50, "show the last `N` records, 1..10000")
	f.StringVar(&o.target, "target", "", "only show records for this target `ID`")
	return f, &o
}

// handleHistory prints the last records of the audit history as a JSON
// array, which is empty, not null, before the first record.
func handleHistory(statePath string, args []string) error {
	f, o := historyCommandLine()
	if err := f.ParseNone(args); err != nil {
		return err
	}
	if o.limit < 1 || o.limit > 10000 {
		return f.Errorf("--limit must be 1..10000")
	}
	rows, err := store.ReadHistory(store.HistoryPath(statePath), o.limit, o.target)
	if err != nil {
		return err
	}
	if rows == nil {
		rows = []store.HistoryRecord{}
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(runtimeOutput, string(data))
	return nil
}

// runOptions are the options of once, watch, and run NAME.
type runOptions struct{ apply, dryRun bool }

// runCommandLine describes once, watch, and run NAME.
func runCommandLine(command string) (*cmdline.Line, *runOptions) {
	synopsis, summary := "--config FILE "+command+" [--apply | --dry-run]", "Confirm the current IPv4 and process actions once."
	switch command {
	case "watch":
		summary = "Monitor connectivity and IP changes until stopped."
	case "run":
		synopsis, summary = "--config FILE run NAME [--apply | --dry-run]", "Run one named action with the confirmed current IP."
	}
	f := cmdline.New(command, synopsis, summary)
	var o runOptions
	f.BoolVar(&o.apply, "apply", false, "allow configured external actions")
	f.BoolVar(&o.dryRun, "dry-run", false, "preview only (the default)")
	return f, &o
}

// handleRun serves once, watch, and run NAME: the commands that may execute actions.
func handleRun(ctx context.Context, c config.Config, statePath, command string, args []string, verbose bool) error {
	f, o := runCommandLine(command)
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	name := ""
	if command == "run" {
		if len(positional) != 1 {
			return f.Errorf("expected one action name")
		}
		name = positional[0]
		if _, ok := c.Actions[name]; !ok {
			return f.Errorf("unknown action %q; this profile has %s", name, strings.Join(config.ActionNames(c), ", "))
		}
	} else if len(positional) != 0 {
		return f.Errorf("unexpected arguments %q", positional)
	}
	if o.apply && o.dryRun {
		return f.Errorf("choose --apply or --dry-run")
	}
	if c, err = config.WithIdentity(c); err != nil {
		return err
	}
	if o.apply {
		unlock, err := store.Lock(statePath)
		if err != nil {
			return err
		}
		defer unlock()
	}
	e, err := engine.Open(c, statePath, o.apply, verbose, eventLog())
	if err != nil {
		return err
	}
	switch command {
	case "once":
		return e.Once(ctx)
	case "watch":
		releaseOwnConsole()
		return e.Watch(ctx)
	default:
		return e.Manual(ctx, name)
	}
}
