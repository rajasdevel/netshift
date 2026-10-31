// Package service installs and controls the per-profile background service:
// a launchd LaunchAgent on macOS, a systemd user unit on Linux, and a Task
// Scheduler task on Windows (see scheduler.go). Nothing it does needs root
// or an administrator.
package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
)

// Host is the account and machine a native service belongs to.
// CurrentHost reads it from the os package; tests inject their own.
type Host struct {
	GOOS string // "darwin" (launchd), "linux" (systemd --user), or "windows" (Task Scheduler)
	UID  int    // selects the launchd gui/UID domain
	Home string // the user's home: service paths and working directory
	// UserSID is the Windows account's security identifier, which the
	// scheduled task runs as.
	UserSID string
	// ConfigDir holds the installed binary, profiles, and (on Linux and
	// Windows) service definitions: ~/Library/Application Support on macOS
	// and %LOCALAPPDATA% on Windows. On Linux it is the directory the
	// systemd user manager searches, which ResolveHost reads from the
	// manager; until then it is ~/.config.
	ConfigDir  string
	Executable string // the running binary, copied on install
	Getenv     func(string) string
	// ManagerEnvironment returns the systemd user manager's environment, as
	// systemctl --user show-environment prints it. nil skips the query.
	ManagerEnvironment func(context.Context) ([]byte, error)
}

// CurrentHost describes the running user's account on this machine.
func CurrentHost() Host {
	// Missing values are reported by NewSpec and writeServiceFiles.
	home, _ := os.UserHomeDir()
	executable, _ := os.Executable()
	h := HostFor(runtime.GOOS, os.Getuid(), home, executable, os.Getenv)
	if h.GOOS == "windows" {
		// On Windows the user ID is the account's SID.
		if u, err := user.Current(); err == nil {
			h.UserSID = u.Uid
		}
	}
	return h
}

// HostFor describes an account. Its configuration directory is the one the
// service manager uses, not the shell's: on Linux, systemd --user searches
// its own environment's XDG_CONFIG_HOME, so a value set only in the shell
// would put the unit where systemd never looks.
func HostFor(goos string, uid int, home, executable string, getenv func(string) string) Host {
	h := Host{GOOS: goos, UID: uid, Home: home, Executable: executable, Getenv: getenv}
	if home == "" {
		return h
	}
	switch goos {
	case "darwin":
		h.ConfigDir = filepath.Join(home, "Library", "Application Support")
	case "linux":
		h.ConfigDir = filepath.Join(home, ".config")
		h.ManagerEnvironment = systemdEnvironment
	case "windows":
		// Task Scheduler gives the task the same %LOCALAPPDATA%; the user's
		// local application data stays on this machine.
		if d := getenv("LOCALAPPDATA"); filepath.IsAbs(d) {
			h.ConfigDir = filepath.Clean(d)
		}
	}
	return h
}

// managerTimeout bounds the query for the systemd user manager's environment.
const managerTimeout = 10 * time.Second

// systemdEnvironment asks the systemd user manager for its environment.
func systemdEnvironment(ctx context.Context) ([]byte, error) {
	return proc.Exec{}.Run(ctx, "systemctl", []string{"--user", "show-environment"}, nil)
}

// ResolveHost points a Linux host's ConfigDir at the directory the
// systemd user manager searches: its own XDG_CONFIG_HOME, or ~/.config when
// it has none. An unreadable environment, or a value that is not a plain
// absolute path, is an error rather than a guess.
func ResolveHost(ctx context.Context, host Host) (Host, error) {
	if host.GOOS != "linux" || host.ManagerEnvironment == nil {
		return host, nil
	}
	ctx, cancel := context.WithTimeout(ctx, managerTimeout)
	defer cancel()
	raw, err := host.ManagerEnvironment(ctx)
	if err != nil {
		return host, fmt.Errorf("cannot read the systemd user manager's environment (systemctl --user show-environment): %w", err)
	}
	for line := range strings.Lines(string(raw)) {
		value, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "XDG_CONFIG_HOME=")
		if !ok {
			continue
		}
		// show-environment quotes unusual values as $'...', which is not absolute.
		if !filepath.IsAbs(value) {
			return host, fmt.Errorf("the systemd user manager's XDG_CONFIG_HOME %q is not a plain absolute path", value)
		}
		host.ConfigDir = filepath.Clean(value)
	}
	return host, nil
}

// Spec is everything one profile's native service definition holds.
type Spec struct {
	Platform string // "darwin", "linux", or "windows"
	Label    string // launchd label, systemd unit name, or Task Scheduler task name
	Path     string // the LaunchAgent plist, systemd unit file, or task XML
	Domain   string // launchd domain, gui/UID
	UserSID  string // the Windows account the task runs as
	Binary   string // installed executable, shared by the user's profiles
	Config   string // installed copy of the profile
	State    string
	Source   string // absolute path of the profile the service was installed from
	Home     string // working directory of the watcher and its hooks
	PATH     string
	LogPath  string // macOS and Windows event log; Linux uses the journal
	ErrPath  string // macOS standard error, which keeps Go panics
	// Environment holds the variables the watcher or its CLIs need to reach
	// the network.
	Environment map[string]string
}

// serviceEnvironment lists the variables an installed service keeps.
var serviceEnvironment = []string{"AZURE_CONFIG_DIR", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}

// Operations are the operations of the service command.
var Operations = []string{"print", "install", "start", "stop", "status", "uninstall"}

const (
	// managedMarker is in every definition NetShift writes; NetShift never
	// replaces or removes a definition without it.
	managedMarker = "Managed by NetShift"
	// SourceMarker records the profile file a definition was installed from.
	SourceMarker = "NetShift source: "
)

// NewSpec returns the native service definition of profile c for
// host: its label, file paths, and the environment it keeps. source is the
// profile file it is installed from, and state the state file it uses.
func NewSpec(c config.Config, source, state string, host Host) (Spec, error) {
	s := Spec{Platform: host.GOOS, Source: source, State: state, Home: host.Home, UserSID: host.UserSID, Environment: map[string]string{}}
	if !slices.Contains(platforms, host.GOOS) {
		return s, errors.New("native services support macOS, Linux, and Windows only")
	}
	if host.Home == "" || host.ConfigDir == "" {
		if host.GOOS == "windows" {
			return s, errors.New("cannot determine the user's profile and local application data directories; check USERPROFILE and LOCALAPPDATA")
		}
		return s, errors.New("cannot determine the user's home and configuration directories; check HOME")
	}
	getenv := host.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	s.PATH = getenv("PATH")
	for _, k := range serviceEnvironment {
		if v := getenv(k); v != "" {
			s.Environment[k] = v
		}
	}
	base := filepath.Join(host.ConfigDir, "netshift")
	if host.GOOS != "linux" {
		base = filepath.Join(host.ConfigDir, "NetShift")
	}
	s.Binary = filepath.Join(base, "bin", "netshift")
	s.Config = filepath.Join(base, "profiles", c.Profile+".json")
	switch host.GOOS {
	case "windows":
		s.Binary += ".exe"
		s.Label = "NetShift-" + c.Profile
		s.Path = filepath.Join(base, "tasks", c.Profile+".xml")
		s.LogPath = filepath.Join(base, "logs", c.Profile+".log")
	case "darwin":
		s.Label = "dev.netshift." + c.Profile
		s.Domain = "gui/" + strconv.Itoa(host.UID)
		logs := filepath.Join(host.Home, "Library", "Logs", "NetShift")
		s.LogPath = filepath.Join(logs, c.Profile+".log")
		s.ErrPath = filepath.Join(logs, c.Profile+".stderr.log")
		s.Path = filepath.Join(host.Home, "Library", "LaunchAgents", s.Label+".plist")
	default:
		s.Label = "netshift-" + c.Profile + ".service"
		s.Path = filepath.Join(host.ConfigDir, "systemd", "user", s.Label)
	}
	return s, nil
}

// platforms are the values of Host.GOOS that have a native service.
var platforms = []string{"darwin", "linux", "windows"}

// Render returns the plist, unit file, or task XML for s. It refuses values
// the format cannot carry rather than writing something that runs
// differently.
func Render(s Spec) ([]byte, error) {
	args := []string{s.Binary, "--config", s.Config, "--state", s.State}
	if s.LogPath != "" {
		args = append(args, "--log-file", s.LogPath)
	}
	args = append(args, "watch", "--apply")
	env := map[string]string{"PATH": s.PATH}
	maps.Copy(env, s.Environment)
	switch s.Platform {
	case "darwin":
		return renderPlist(s, args, env)
	case "linux":
		return renderUnit(s, args, env)
	case "windows":
		return renderTask(s, args)
	}
	return nil, errors.New("native services support macOS, Linux, and Windows only")
}

// renderPlist writes a LaunchAgent that runs args with env. It records the
// source profile in a comment and refuses values XML cannot represent.
func renderPlist(s Spec, args []string, env map[string]string) ([]byte, error) {
	var b strings.Builder
	var bad error
	text := func(v string) string {
		escaped, err := xmlText(v)
		if err != nil && bad == nil {
			bad = err
		}
		return escaped
	}
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<!-- " + managedMarker + " -->\n")
	if s.Source != "" {
		// encodeSource never leaves "--", which XML comments cannot contain.
		b.WriteString("<!-- " + SourceMarker + encodeSource(s.Source) + " -->\n")
		text(s.Source) // comments allow the same characters as text
	}
	b.WriteString("<plist version=\"1.0\"><dict>\n")
	b.WriteString("<key>Label</key><string>" + text(s.Label) + "</string>\n<key>ProgramArguments</key><array>\n")
	for _, arg := range args {
		b.WriteString("<string>" + text(arg) + "</string>\n")
	}
	b.WriteString("</array>\n")
	if s.Home != "" {
		b.WriteString("<key>WorkingDirectory</key><string>" + text(s.Home) + "</string>\n")
	}
	b.WriteString("<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>ProcessType</key><string>Standard</string>\n<key>Umask</key><integer>63</integer>\n")
	b.WriteString("<key>EnvironmentVariables</key><dict>\n")
	for _, k := range slices.Sorted(maps.Keys(env)) {
		b.WriteString("<key>" + text(k) + "</key><string>" + text(env[k]) + "</string>\n")
	}
	b.WriteString("</dict>\n")
	// The event log goes to --log-file. Standard error keeps Go panics and
	// fatal errors; launchd appends to it and nothing rotates it.
	errPath := s.ErrPath
	if errPath == "" {
		errPath = os.DevNull
	}
	b.WriteString("<key>StandardOutPath</key><string>/dev/null</string>\n<key>StandardErrorPath</key><string>" + text(errPath) + "</string>\n</dict></plist>\n")
	if bad != nil {
		return nil, fmt.Errorf("cannot write the LaunchAgent: %w", bad)
	}
	return []byte(b.String()), nil
}

// renderUnit writes a systemd user unit. Restarts are paced by RestartSec
// alone: StartLimitIntervalSec=0 never gives up, because a watcher that a
// short crash loop (say, during login before the network is up) leaves
// permanently failed is worse than one restart every 10 seconds. The
// RestartSteps/RestartMaxDelaySec back-off needs systemd 254, newer than
// Debian 12's 252.
func renderUnit(s Spec, args []string, env map[string]string) ([]byte, error) {
	keys := slices.Sorted(maps.Keys(env))
	for _, v := range slices.Concat(args, keys, slices.Collect(maps.Values(env))) {
		if strings.ContainsRune(v, 0) {
			return nil, fmt.Errorf("cannot write the systemd unit: %q contains a NUL character", v)
		}
	}
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = unitQuote(strings.ReplaceAll(arg, "$", "$$"))
	}
	var b strings.Builder
	b.WriteString("# " + managedMarker + "\n")
	if s.Source != "" {
		b.WriteString("# " + SourceMarker + encodeSource(s.Source) + "\n")
	}
	b.WriteString("[Unit]\nDescription=NetShift network events (" + s.Label + ")\nStartLimitIntervalSec=0\n\n")
	b.WriteString("[Service]\nType=exec\nExecStart=" + strings.Join(quoted, " ") + "\n")
	for _, k := range keys {
		b.WriteString("Environment=" + unitQuote(k+"="+env[k]) + "\n")
	}
	b.WriteString("WorkingDirectory=~\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=15\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n")
	return []byte(b.String()), nil
}

// xmlText escapes s for XML character data. It rejects invalid UTF-8 and the
// control characters XML 1.0 cannot represent, which encoding/xml would
// silently replace with U+FFFD.
func xmlText(s string) (string, error) {
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return "", fmt.Errorf("%q is not valid UTF-8", s)
			}
		}
		if !xmlChar(r) {
			return "", fmt.Errorf("%q contains U+%04X, which XML cannot represent", s, r)
		}
	}
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

// xmlChar reports whether r is in the XML 1.0 Char production.
func xmlChar(r rune) bool {
	return r == '\t' || r == '\n' || r == '\r' ||
		r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF
}

// unitQuote quotes s as one systemd unit-file word, with "%" escaped.
func unitQuote(s string) string { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }

// encodeSource percent-encodes the bytes of a path that cannot appear in an
// XML or unit-file comment line: "%", "\", line breaks, and a "-" before
// another "-". url.PathUnescape reverses it.
func encodeSource(path string) string {
	var b strings.Builder
	for i := range len(path) {
		c := path[i]
		if c == '%' || c == '\\' || c == '\n' || c == '\r' || c == '-' && i+1 < len(path) && path[i+1] == '-' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// DefinitionSource returns the profile path recorded in a definition. found is
// false for a definition that does not record one.
func DefinitionSource(definition []byte) (source string, found bool, err error) {
	for line := range strings.Lines(string(definition)) {
		line = strings.TrimRight(line, "\r\n")
		var encoded string
		if rest, ok := strings.CutPrefix(line, "<!-- "+SourceMarker); ok {
			encoded, found = strings.CutSuffix(rest, " -->")
		} else if rest, ok := strings.CutPrefix(line, "# "+SourceMarker); ok {
			encoded, found = rest, true
		}
		if found {
			source, err = url.PathUnescape(encoded)
			return source, true, err
		}
	}
	return "", false, nil
}

// Control starts, stops, or reports this profile's service, and no
// other job, unit, or task.
func Control(ctx context.Context, runner proc.Runner, s Spec, operation string) ([]byte, error) {
	if s.Platform == "windows" {
		switch operation {
		case "start":
			return startTask(ctx, runner, s)
		case "stop":
			return nil, stopTask(ctx, runner, s)
		case "status":
			return taskStatus(ctx, runner, s)
		}
		return nil, errors.New("unknown service operation")
	}
	if s.Platform == "darwin" {
		target := s.Domain + "/" + s.Label
		switch operation {
		case "start":
			if _, err := runner.Run(ctx, "launchctl", []string{"enable", target}, nil); err != nil {
				return nil, err
			}
			loaded, err := launchdLoaded(ctx, runner, target)
			if err != nil {
				return nil, err
			}
			if loaded {
				return runner.Run(ctx, "launchctl", []string{"kickstart", target}, nil)
			}
			return runner.Run(ctx, "launchctl", []string{"bootstrap", s.Domain, s.Path}, nil)
		case "stop":
			if _, err := runner.Run(ctx, "launchctl", []string{"disable", target}, nil); err != nil {
				return nil, err
			}
			loaded, err := launchdLoaded(ctx, runner, target)
			if err != nil || !loaded {
				return nil, err
			}
			return nil, bootout(ctx, runner, target)
		case "status":
			return runner.Run(ctx, "launchctl", []string{"print", target}, nil)
		}
	} else {
		switch operation {
		case "start":
			return runner.Run(ctx, "systemctl", []string{"--user", "enable", "--now", s.Label}, nil)
		case "stop":
			return runner.Run(ctx, "systemctl", []string{"--user", "disable", "--now", s.Label}, nil)
		case "status":
			return runner.Run(ctx, "systemctl", []string{"--user", "status", "--no-pager", s.Label}, nil)
		}
	}
	return nil, errors.New("unknown service operation")
}

// launchdLoaded reports whether launchd has the job target loaded. Only a
// definite answer counts: launchctl print succeeds for a loaded job and, for
// a missing one, exits 113 or says "Could not find service". Any other
// failure, such as a timeout, is an error, never "not loaded".
func launchdLoaded(ctx context.Context, runner proc.Runner, target string) (bool, error) {
	out, err := runner.Run(ctx, "launchctl", []string{"print", target}, nil)
	switch {
	case err == nil:
		return true, nil
	case LaunchdMissing(out, err):
		return false, nil
	}
	return false, fmt.Errorf("cannot tell whether %s is loaded: %w", target, err)
}

// LaunchdNotFound is launchctl's exit status for a job it does not have.
const LaunchdNotFound = 113

// LaunchdMissing reports whether a failed launchctl print said the job does
// not exist, by its exit status or its message.
func LaunchdMissing(out []byte, err error) bool {
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == LaunchdNotFound {
		return true
	}
	return strings.Contains(err.Error(), "Could not find service") || bytes.Contains(out, []byte("Could not find service"))
}

// systemdActive reports whether systemd runs the unit or is starting,
// stopping, or restarting it, as it does between the restarts of a failing
// watcher. Only a definite answer from systemctl is-active counts; any other
// failure, such as a timeout or an unreachable user manager, is an error.
func systemdActive(ctx context.Context, runner proc.Runner, unit string) (bool, error) {
	out, err := runner.Run(ctx, "systemctl", []string{"--user", "is-active", unit}, nil)
	if err == nil {
		return true, nil
	}
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		switch strings.TrimSpace(string(out)) {
		case "inactive", "failed", "unknown":
			return false, nil
		case "activating", "deactivating", "reloading", "refreshing":
			return true, nil
		}
	}
	return false, fmt.Errorf("cannot tell whether %s is active: %w", unit, err)
}

// serviceLoaded reports whether the service manager has s loaded (launchd),
// active (systemd), or registered (Task Scheduler).
func serviceLoaded(ctx context.Context, runner proc.Runner, s Spec) (bool, error) {
	if s.Platform == "windows" {
		state, err := queryTask(ctx, runner, s)
		return state.registered, err
	}
	if s.Platform == "darwin" {
		return launchdLoaded(ctx, runner, s.Domain+"/"+s.Label)
	}
	return systemdActive(ctx, runner, s.Label)
}

// Polling bounds for a launchd job to leave its domain after bootout.
const (
	unloadTimeout = 10 * time.Second
	unloadPoll    = 200 * time.Millisecond
)

// bootout removes target from launchd. launchctl bootout can return before the
// job is gone (or fail with "Operation now in progress"), and an immediate
// bootstrap then fails with "Bootstrap failed: 5: Input/output error". So it
// waits, boundedly, until launchctl print says the job is gone. It keeps
// polling while the job is loaded or print gives no definite answer, and at
// the deadline returns the last answer's error.
func bootout(ctx context.Context, runner proc.Runner, target string) error {
	_, err := runner.Run(ctx, "launchctl", []string{"bootout", target}, nil)
	ctx, cancel := context.WithTimeout(ctx, unloadTimeout)
	defer cancel()
	for {
		loaded, printErr := launchdLoaded(ctx, runner, target)
		if printErr == nil && !loaded {
			return nil // unloaded; a bootout error was transient
		}
		select {
		case <-ctx.Done():
			if printErr != nil {
				return errors.Join(err, printErr)
			}
			return errors.Join(err, fmt.Errorf("%s is still loaded after bootout: %w", target, ctx.Err()))
		case <-time.After(unloadPoll):
		}
	}
}

// InstallOptions are service install's flags.
type InstallOptions struct {
	Start, Replace bool
	Out            io.Writer // receives notices
}

// Install copies the binary and a host-bound profile, writes the
// definition, and then leaves the service stopped and disabled, or restarts
// it when start is set. It never takes over a definition it did not write,
// or one installed from another profile file unless replace is set.
func Install(ctx context.Context, c config.Config, s Spec, opts InstallOptions, host Host, runner proc.Runner) error {
	prior, notice, err := priorDefinition(s, opts.Replace)
	if err != nil {
		return err
	}
	installed, err := installedProfile(c)
	if err != nil {
		return err
	}
	definition, err := Render(s)
	if err != nil {
		return err
	}
	if notice != "" {
		fmt.Fprintln(opts.Out, "Notice:", notice)
	}
	if s.Platform == "windows" {
		return installTask(ctx, s, opts, host, runner, installed, definition)
	}
	if !opts.Start && (s.Platform == "darwin" || prior != nil) {
		// launchd loads every plist in LaunchAgents at the next login, and an
		// enabled unit stays enabled when its file changes. Disable and stop
		// the job before writing, so a later failure cannot leave a
		// definition that runs watch --apply without --start.
		if _, err = Control(ctx, runner, s, "stop"); err != nil {
			return err
		}
	}
	if err = writeServiceFiles(s, installed, definition, host.Executable); err != nil {
		return err
	}
	if s.Platform == "linux" {
		if _, err = runner.Run(ctx, "systemctl", []string{"--user", "daemon-reload"}, nil); err != nil {
			return err
		}
	}
	if opts.Start {
		return restartService(ctx, runner, s, bytes.Equal(prior, definition))
	}
	if s.Platform == "linux" {
		// Also catch an enablement left behind by a removed unit file.
		_, err = Control(ctx, runner, s, "stop")
	}
	return err
}

// priorDefinition reads the definition an install would replace; it is nil
// when none exists. The notice explains a replacement the user should know of.
func priorDefinition(s Spec, replace bool) (prior []byte, notice string, err error) {
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("refusing to replace a symlink or non-regular service definition: %s", s.Path)
	}
	if prior, err = os.ReadFile(s.Path); err != nil {
		return nil, "", err
	}
	if !bytes.Contains(prior, []byte(managedMarker)) {
		return nil, "", fmt.Errorf("refusing to replace an unmanaged service definition: %s", s.Path)
	}
	source, found, err := DefinitionSource(prior)
	if err != nil {
		source = "an unrecognized profile path"
	}
	switch {
	case !found:
		return prior, "replacing a service definition that does not record its profile file", nil
	case err == nil && (source == s.Source || fsx.SameFile(source, s.Source)):
		return prior, "", nil
	case !replace:
		return nil, "", fmt.Errorf("%s was installed from %s, not %s; profiles with the same name share one service; add --replace to install this profile in its place", s.Label, source, s.Source)
	}
	return prior, "replacing the service installed from " + source, nil
}

// installedProfile binds the profile copy to this host: it pins the identity
// and resolves each action's executable to an absolute path. The project
// profile stays portable.
func installedProfile(c config.Config) (config.Config, error) {
	c, err := config.WithIdentity(c)
	if err != nil {
		return c, err
	}
	actions := make(map[string]config.ActionConfig, len(c.Actions))
	for _, name := range config.ActionNames(c) {
		a := c.Actions[name]
		program := a.AzureCLI
		if a.Type == config.ActionCommand {
			program = a.Command[0]
		}
		resolved, err := exec.LookPath(program)
		if err != nil {
			return c, fmt.Errorf("%s executable: %w", name, err)
		}
		if resolved, err = filepath.Abs(resolved); err != nil {
			return c, err
		}
		if a.Type == config.ActionCommand {
			a.Command = slices.Clone(a.Command)
			a.Command[0] = resolved
		} else {
			a.AzureCLI = resolved
		}
		actions[name] = a
	}
	c.Actions = actions
	return c, nil
}

// installTask installs a Windows task. Task Scheduler has no state in which
// a changed definition waits for the next start, and a running watcher keeps
// the installed binary open, so the task is stopped and disabled before
// anything is written, and registered last: disabled without --start, so
// that nothing runs, and otherwise enabled and started.
func installTask(ctx context.Context, s Spec, opts InstallOptions, host Host, runner proc.Runner, installed config.Config, definition []byte) error {
	if err := stopTask(ctx, runner, s); err != nil {
		return err
	}
	if err := writeServiceFiles(s, installed, definition, host.Executable); err != nil {
		return err
	}
	if err := registerTask(ctx, runner, s, definition, opts.Start); err != nil {
		return err
	}
	if opts.Start {
		_, err := startTask(ctx, runner, s)
		return err
	}
	return nil
}

// writeServiceFiles writes the definition last, so it never names files that
// were not written.
func writeServiceFiles(s Spec, c config.Config, definition []byte, executable string) error {
	if executable == "" {
		return errors.New("cannot locate the running netshift executable")
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if err = installBinary(s, binary); err != nil {
		return err
	}
	profile, err := config.JSON(c)
	if err != nil {
		return err
	}
	if err = fsx.AtomicWrite(s.Config, profile, 0600); err != nil {
		return err
	}
	for _, p := range []string{s.LogPath, s.ErrPath} {
		if p == "" {
			continue
		}
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
	}
	return fsx.AtomicWrite(s.Path, definition, 0600)
}

// installBinary writes the shared binary. Windows cannot replace an
// executable that runs, as another profile's watcher may; it can rename one.
// So an unchanged binary is left alone, and a changed one that cannot be
// replaced is first moved aside to a name that later installs remove once
// nothing runs it.
func installBinary(s Spec, binary []byte) error {
	if s.Platform != "windows" {
		return fsx.AtomicWrite(s.Binary, binary, 0700)
	}
	if current, err := fsx.ReadFileLimit(s.Binary, maxBinary); err == nil && bytes.Equal(current, binary) {
		return nil
	}
	err := fsx.AtomicWrite(s.Binary, binary, 0700)
	if errors.Is(err, fs.ErrPermission) { // in use
		aside := s.Binary + "." + strconv.FormatInt(time.Now().UnixNano(), 36) + ".old"
		if os.Rename(s.Binary, aside) != nil {
			return err
		}
		if err = fsx.AtomicWrite(s.Binary, binary, 0700); err != nil {
			// Put it back: other profiles' tasks name this path.
			return errors.Join(err, os.Rename(aside, s.Binary))
		}
	} else if err != nil {
		return err
	}
	// Remove binaries moved aside earlier; one still running stays.
	old, _ := filepath.Glob(s.Binary + ".*.old")
	for _, path := range old {
		_ = os.Remove(path)
	}
	return nil
}

// maxBinary bounds the installed binary NetShift reads back to compare.
const maxBinary = 256 << 20

// restartService enables the service and restarts only its own job or unit.
// An unchanged LaunchAgent restarts in place with kickstart -k; a changed one
// must be booted out and bootstrapped for launchd to read it again.
func restartService(ctx context.Context, runner proc.Runner, s Spec, unchanged bool) error {
	if s.Platform == "linux" {
		if _, err := runner.Run(ctx, "systemctl", []string{"--user", "enable", s.Label}, nil); err != nil {
			return err
		}
		_, err := runner.Run(ctx, "systemctl", []string{"--user", "restart", s.Label}, nil)
		return err
	}
	target := s.Domain + "/" + s.Label
	if _, err := runner.Run(ctx, "launchctl", []string{"enable", target}, nil); err != nil {
		return err
	}
	loaded, err := launchdLoaded(ctx, runner, target)
	if err != nil {
		return err
	}
	if loaded {
		if unchanged {
			_, err := runner.Run(ctx, "launchctl", []string{"kickstart", "-k", target}, nil)
			return err
		}
		if err := bootout(ctx, runner, target); err != nil {
			return err
		}
	}
	_, err = runner.Run(ctx, "launchctl", []string{"bootstrap", s.Domain, s.Path}, nil)
	return err
}

// WithTimeout bounds one service command, including its waits.
func WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
