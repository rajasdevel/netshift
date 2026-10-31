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
	"slices"
	"strings"
	"syscall"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
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
  netshift [--config FILE] [global options] COMMAND [options]
  netshift init azure | command [options]
  netshift help [COMMAND] | version | completion bash | zsh | fish

Global options (before COMMAND):
  --config FILE     Profile (JSON) to use. Default: $NETSHIFT_CONFIG.
                    Required except for init, help, version, and completion.
  --state FILE      State file. Default: the native user state directory.
  --log-file FILE   Write the event log to FILE (1 MiB plus one backup).
  --verbose         Also log targets that were verified unchanged.
  --version         Print the version.

Environment:
  NETSHIFT_CONFIG   Absolute path of the profile to use when --config is not
                    given. An explicit --config wins. While a command runs,
                    NetShift sets it to the profile in use, so hooks see it.

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
  init command --profile NAME --output FILE
                    Write a starter profile with one command action.
  completion bash | zsh | fish
                    Print a shell completion script.

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

// configEnv names the environment variable that supplies the profile when
// --config is not given.
const configEnv = "NETSHIFT_CONFIG"

// globalOptions are the options before COMMAND.
type globalOptions struct {
	config, state, logFile string
	verbose, version       bool
}

// globalCommandLine describes the options before COMMAND. The overview in
// usage documents them; completion reads them from here.
func globalCommandLine() (*cmdline.Line, *globalOptions) {
	f := cmdline.New("netshift", "[--config FILE] [global options] COMMAND [options]", "")
	var o globalOptions
	f.StringVar(&o.config, "config", "", "profile `FILE` (JSON) to use; defaults to $"+configEnv)
	f.StringVar(&o.state, "state", "", "state `FILE` (defaults to the native user state directory)")
	f.BoolVar(&o.verbose, "verbose", false, "also log targets that were verified unchanged")
	f.StringVar(&o.logFile, "log-file", "", "write the event log to this `FILE` (1 MiB plus one backup)")
	f.BoolVar(&o.version, "version", false, "print the version")
	return f, &o
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
	// line returns the command's options and usage, without a profile. For a
	// command with several forms it describes them all, and formLine, when
	// set, returns the line of the form that the arguments choose.
	line     func() *cmdline.Line
	formLine func(args []string) *cmdline.Line
	// profile commands need --config; cli loads it and resolves --state.
	profile bool
	// refusesProfile commands reject --config and --state.
	refusesProfile bool
	// identity commands resolve the user@host identity before parsing their
	// arguments. once, watch, and run resolve it after parsing instead.
	identity bool
	// choices are the words the first argument may be, for completion.
	choices []string
	run     func(ctx context.Context, in invocation, args []string) error
}

// commands returns the command table, which drives dispatch, help COMMAND,
// identity resolution, and shell completion. A new command needs one entry
// here and a line in the usage text.
func commands() []command {
	table := []command{
		{name: "help", line: helpCommandLine,
			run: func(_ context.Context, _ invocation, args []string) error { return handleHelp(args) }},
		{name: "version", line: versionCommandLine,
			run: func(_ context.Context, _ invocation, args []string) error { return handleVersion(args) }},
		{name: "completion", line: completionCommandLine, choices: completionShells,
			run: func(_ context.Context, _ invocation, args []string) error { return handleCompletion(args) }},
		{name: "init", line: lineOf(initCommandLine), formLine: initFormLine, refusesProfile: true, choices: initKinds,
			run: func(ctx context.Context, _ invocation, args []string) error {
				return handleInit(ctx, args, proc.Exec{})
			}},
		{name: "validate", line: validateCommandLine, profile: true,
			run: func(_ context.Context, in invocation, args []string) error {
				return handleValidate(in.config, in.configPath, args)
			}},
		{name: "identity", line: identityCommandLine, profile: true,
			run: func(_ context.Context, in invocation, args []string) error { return handleIdentity(in.config, args) }},
		{name: "test-event", line: lineOf(testEventCommandLine), profile: true, choices: testEvents,
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
		{name: "service", line: lineOf(serviceCommandLine), profile: true, choices: service.Operations,
			run: func(ctx context.Context, in invocation, args []string) error {
				return handleService(ctx, in.config, in.configPath, in.statePath, args)
			}},
		{name: "devices", line: func() *cmdline.Line { return engine.DevicesCommandLine(new(engine.DevicesOptions)) }, profile: true, identity: true,
			choices: engine.DeviceOperations,
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
	// help takes any command's name.
	var names []string
	for _, c := range table {
		names = append(names, c.name)
	}
	slices.Sort(names)
	for i := range table {
		if table[i].name == "help" {
			table[i].choices = names
		}
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
	f, g := globalCommandLine()
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(runtimeOutput, usage)
			return err
		}
		return &cmdline.UsageError{Message: cmdline.Dashes(err.Error())}
	}
	given := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	// An explicit but empty --config, such as --config "$UNSET", must never
	// fall back to NETSHIFT_CONFIG and act on another profile.
	if given["config"] && strings.TrimSpace(g.config) == "" {
		return &cmdline.UsageError{Message: "--config needs a FILE"}
	}
	if g.version {
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
	if cmd.formLine != nil {
		line = cmd.formLine(rest)
	}
	// Answer -h, and a global option placed after the command, before
	// loading a profile, so help works without --config. Handlers parse
	// their arguments again and report any other problem.
	if _, err := line.ParseArgs(rest); errors.Is(err, flag.ErrHelp) || errors.Is(err, cmdline.ErrGlobalAfterCommand) {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(runtimeOutput, line.Help())
		}
		return err
	}
	// Only an explicit --config or --state is refused, even an empty one;
	// NETSHIFT_CONFIG is just a default.
	if cmd.refusesProfile && (given["config"] || given["state"]) {
		return &cmdline.UsageError{Message: name + " uses --output rather than --config/--state"}
	}
	in := invocation{verbose: g.verbose}
	if !cmd.profile {
		return cmd.run(ctx, in, rest)
	}
	var err error
	if in.configPath, err = profilePath(g.config, line); err != nil {
		return err
	}
	if in.config, err = config.Load(in.configPath); err != nil {
		if g.config == "" {
			return fmt.Errorf("%s=%q: %w", configEnv, in.configPath, err)
		}
		return err
	}
	// Hooks, and anything they start, see the profile in use, not a
	// NETSHIFT_CONFIG inherited from the caller.
	restore, err := setenvWhileRunning(configEnv, in.configPath)
	if err != nil {
		return err
	}
	defer restore()
	if g.state == "" {
		in.statePath, err = store.DefaultPath(in.config.Profile)
	} else {
		in.statePath, err = filepath.Abs(g.state)
	}
	if err != nil {
		return err
	}
	for _, p := range []string{in.statePath, store.HistoryPath(in.statePath), in.statePath + ".lock"} {
		if fsx.SameFile(p, in.configPath) {
			return errors.New("state, history, and lock files must not be the profile")
		}
	}
	if g.logFile != "" {
		path, err := filepath.Abs(g.logFile)
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

// profilePath returns the absolute path of the profile to load: --config
// when given, or else $NETSHIFT_CONFIG. The variable must hold an absolute
// path, because it outlives the directory it was set in; a relative one
// would pick a different file, and install a different service source, in
// each directory. line is the command's, for the usage error.
func profilePath(flagValue string, line *cmdline.Line) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	path := os.Getenv(configEnv)
	switch {
	case path == "":
		return "", &cmdline.UsageError{Message: "--config FILE is required, or set " + configEnv, Usage: line.Help()}
	case !filepath.IsAbs(path):
		return "", &cmdline.UsageError{Message: fmt.Sprintf("%s must be an absolute path, not %q", configEnv, path)}
	}
	return filepath.Clean(path), nil
}

// setenvWhileRunning sets key to value until restore puts back what it was.
// The process exits after its one command, so restoring matters only to
// tests, which run many commands in one process.
func setenvWhileRunning(key, value string) (restore func(), err error) {
	old, had := os.LookupEnv(key)
	if err = os.Setenv(key, value); err != nil {
		return nil, err
	}
	return func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	}, nil
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
	return cmdline.New("validate", "[--config FILE] validate", "Check the profile, without network access.")
}

// handleValidate reports a profile that config.Load already validated, and
// the file it came from, which NETSHIFT_CONFIG may have chosen.
func handleValidate(c config.Config, path string, args []string) error {
	if err := validateCommandLine().ParseNone(args); err != nil {
		return err
	}
	fmt.Fprintf(runtimeOutput, "Valid profile %q in %s with actions: %s.\n", c.Profile, path, strings.Join(config.ActionNames(c), ", "))
	return nil
}

// identityCommandLine describes identity.
func identityCommandLine() *cmdline.Line {
	return cmdline.New("identity", "[--config FILE] identity", "Show this profile's user@host identity.")
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
	f := cmdline.New("history", "[--config FILE] history [--limit N] [--target ID]", "Show the persistent rule/IP audit history.")
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
	synopsis, summary := "[--config FILE] "+command+" [--apply | --dry-run]", "Confirm the current IPv4 and process actions once."
	switch command {
	case "watch":
		summary = "Monitor connectivity and IP changes until stopped."
	case "run":
		synopsis, summary = "[--config FILE] run NAME [--apply | --dry-run]", "Run one named action with the confirmed current IP."
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
		return e.Watch(ctx)
	default:
		return e.Manual(ctx, name)
	}
}
