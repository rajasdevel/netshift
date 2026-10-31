// Package doctor checks that a profile can run on this machine: the profile
// and state, IP discovery, each action's executable and arguments, the
// native service, notifications, and, on request, Azure sign-in and the
// post-action checks. It reports and never changes anything.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
	"github.com/rajasdevel/netshift/internal/store"
)

// Diagnosis is one doctor result: a PASS, WARN, or FAIL with its detail.
type Diagnosis struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

const (
	StatusPass = "PASS"
	StatusWarn = "WARN"
	StatusFail = "FAIL"
)

// Checkup is one diagnosis run. It reads state and asks service managers and
// optional tools about it; it never runs actions or changes anything.
type Checkup struct {
	Config   config.Config
	Source   string // the profile file; "" skips the installed-source check
	State    string
	Runner   proc.Runner
	Observer discovery.Observer
	Host     service.Host
	Azure    bool
	Checks   bool
	rows     []Diagnosis
}

// add records one result.
func (d *Checkup) add(name, status, detail string) {
	d.rows = append(d.rows, Diagnosis{Name: name, Status: status, Detail: detail})
}

// Run performs every selected check, in a stable order, and returns the results.
func (d *Checkup) Run(ctx context.Context) []Diagnosis {
	d.add("profile", StatusPass, "schema and action definitions are valid")
	d.identityAndState()
	d.discovery(ctx)
	d.executables()
	d.commandArguments()
	d.service(ctx)
	d.notifications()
	if d.Azure {
		d.azureAuthentication(ctx)
	}
	if d.Checks {
		d.probes(ctx)
	}
	return d.rows
}

// identityAndState resolves the identity of a profile with device
// actions and checks that the saved state is readable and bound to it.
func (d *Checkup) identityAndState() {
	resolved := true
	if config.HasDevices(d.Config) {
		c, err := config.WithIdentity(d.Config)
		if err != nil {
			resolved = false
			d.add("identity", StatusFail, err.Error())
		} else {
			d.Config = c
			d.add("identity", StatusPass, c.Identity)
		}
	}
	s, err := store.Load(d.State)
	switch {
	case err != nil:
		d.add("saved state", StatusFail, err.Error())
	case !resolved:
		d.add("saved state", StatusPass, "readable; identity binding not checked")
	default:
		if err = engine.BindIdentity(d.Config, s); err != nil {
			d.add("saved identity", StatusFail, err.Error())
		} else {
			d.add("saved state", StatusPass, "readable; no reset performed")
		}
	}
}

// discovery asks the IP sources for the current address, as watch does.
func (d *Checkup) discovery(ctx context.Context) {
	o := d.Observer.Observe(ctx, "")
	if o.Verified {
		d.add("IP discovery", StatusPass, "two sources confirmed the current IPv4")
		return
	}
	message := "no agreed public IPv4"
	if o.Err != nil {
		message = o.Err.Error()
	}
	d.add("IP discovery", StatusFail, message)
}

// executables checks that each action's program is executable or on PATH.
func (d *Checkup) executables() {
	programs := map[string]bool{}
	for _, a := range d.Config.Actions {
		if a.Type == config.ActionCommand {
			programs[a.Command[0]] = true
		} else {
			programs[a.AzureCLI] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(programs)) {
		if _, err := exec.LookPath(name); err != nil {
			d.add("executable "+name, StatusFail, "not executable or absent from PATH")
		} else {
			d.add("executable "+name, StatusPass, "available")
		}
	}
}

// commandArguments catches recipe placeholders and missing scripts before a
// hook fails at the first real event.
func (d *Checkup) commandArguments() {
	for _, name := range config.ActionNames(d.Config) {
		a := d.Config.Actions[name]
		if a.Type != config.ActionCommand {
			continue
		}
		problems := ArgumentProblems(a.Command, d.Host.Home)
		if len(problems) == 0 {
			d.add("arguments "+name, StatusPass, argumentsPassed(a.Command))
		}
		for _, p := range problems {
			d.add("arguments "+name, p.Status, p.Detail)
		}
	}
}

// argumentsPassed describes what a command without argument problems was
// checked for, without claiming more than was checked.
func argumentsPassed(argv []string) string {
	paths := 0
	for _, arg := range argv[1:] {
		if filepath.IsAbs(arg) {
			paths++
		}
	}
	switch paths {
	case 0:
		return "no placeholders; no absolute path arguments to check"
	case 1:
		return "no placeholders; the absolute path argument exists"
	}
	return fmt.Sprintf("no placeholders; all %d absolute path arguments exist", paths)
}

// placeholderPath is the script-path placeholder the recipes ship; it must
// be replaced before use.
const placeholderPath = "/absolute/path/to/"

// placeholderValue matches the recipes' value placeholders: a YOUR_ word that
// starts an argument or a path element, so a shell variable such as
// "$YOUR_HOOK" inside sh -c code is not one.
var placeholderValue = regexp.MustCompile(`(^|/)YOUR_[A-Z0-9_]+`)

// ArgumentProblems reports placeholder arguments, absolute paths that do not
// exist, and relative script paths, which resolve against the hook's working
// directory: the user's home under a native service.
func ArgumentProblems(argv []string, home string) []Diagnosis {
	var problems []Diagnosis
	add := func(status, format string, args ...any) {
		problems = append(problems, Diagnosis{Status: status, Detail: fmt.Sprintf(format, args...)})
	}
	script := scriptArgument(argv)
	for i, arg := range argv {
		if strings.Contains(arg, placeholderPath) || placeholderValue.MatchString(arg) {
			add(StatusFail, "placeholder argument %q; replace it with a real value", arg)
			continue
		}
		if i == 0 {
			continue // the executable check covers argv[0]
		}
		switch {
		case filepath.IsAbs(arg):
			if _, err := os.Stat(arg); err == nil {
				continue
			}
			if i == script {
				add(StatusFail, "script %s does not exist", arg)
			} else {
				add(StatusWarn, "path %s does not exist (fine if the hook creates it)", arg)
			}
		case i == script:
			fromHome := filepath.Join(home, arg)
			if _, err := os.Stat(fromHome); home == "" || err != nil {
				add(StatusFail, "relative script %q is not found from the home directory, where services run hooks; use an absolute path", arg)
			} else {
				add(StatusWarn, "relative script %q resolves to %s; use an absolute path", arg, fromHome)
			}
		}
	}
	return problems
}

// interpreterOptions describes an interpreter's single-letter options well
// enough to find the script file it runs. Each string lists option letters.
type interpreterOptions struct {
	noScript string // the program is inline code or standard input (sh -c, sh -s, python -m)
	value    string // takes a value: the rest of the cluster, or else the next argument
	chdir    string // takes a directory to change into, as ruby -C does
	optional string // takes an optional value, only from the rest of the cluster (ruby -W)
	flags    string // takes no value
	plus     bool   // also accepts +x forms with the same letters (shells)
}

var (
	shellOptions  = interpreterOptions{noScript: "cs", value: "oO", flags: "abefhiklmnprtuvxBCDEHPT", plus: true}
	pythonOptions = interpreterOptions{noScript: "cm", value: "WX", flags: "bBdEhiIOPqsSuvVx"}
)

// interpreters run the script named by their first non-option argument. A
// letter an entry does not list, such as perl -l or ruby -S (which searches
// PATH), makes the check give up rather than guess.
var interpreters = map[string]interpreterOptions{
	"sh": shellOptions, "bash": shellOptions, "dash": shellOptions, "zsh": shellOptions, "ksh": shellOptions,
	"fish":      {noScript: "c", value: "CdDfop", flags: "hilnPv"},
	"python":    pythonOptions,
	"python3":   pythonOptions,
	"perl":      {noScript: "eE", value: "I", flags: "acnpstTuUvwWX"},
	"ruby":      {noScript: "e", value: "rIE", chdir: "C", optional: "W0", flags: "acdhlnpsvwyU"},
	"node":      {noScript: "ep", value: "rC", flags: "chiv"},
	"osascript": {noScript: "e", value: "ls", flags: "i"},
}

// scriptArgument returns the index of the script an interpreter runs, or -1
// when argv does not run a script file (inline code such as sh -c, or
// standard input). A form it does not model, such as a long option or an
// unknown option letter, also returns -1: the check can miss a script but
// never fails a valid command.
func scriptArgument(argv []string) int {
	if len(argv) == 0 {
		return -1
	}
	options, ok := interpreters[filepath.Base(argv[0])]
	if !ok {
		return -1
	}
	changedDir := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			i++
		case arg == "-" || strings.HasPrefix(arg, "--"):
			return -1 // standard input, or a long option this check does not model
		case len(arg) > 1 && (arg[0] == '-' || arg[0] == '+' && options.plus):
			next, ok := options.cluster(arg[1:])
			if !ok {
				return -1
			}
			changedDir = changedDir || next == clusterChdir
			if next != clusterDone {
				i++ // the option's value
			}
			continue
		}
		if i >= len(argv) || changedDir && !filepath.IsAbs(argv[i]) {
			return -1 // nothing to run, or relative to another directory
		}
		return i
	}
	return -1
}

// Results of interpreterOptions.cluster.
const (
	clusterDone  = iota // the cluster is complete
	clusterValue        // the next argument is an option's value
	clusterChdir        // the next argument is a directory to change into
)

// cluster reads one option cluster, such as "eu" from -eu or "o" from -o.
// ok is false when the cluster names inline code or standard input, or a
// letter the entry does not list.
func (o interpreterOptions) cluster(letters string) (next int, ok bool) {
	for j := 0; j < len(letters); j++ {
		l := letters[j : j+1]
		switch {
		case strings.Contains(o.noScript, l):
			return 0, false
		case strings.Contains(o.value, l), strings.Contains(o.chdir, l):
			attached := j+1 < len(letters)
			switch {
			case strings.Contains(o.chdir, l) && attached:
				return clusterDone, false // ruby -Cdir: give up on relative scripts
			case strings.Contains(o.chdir, l):
				return clusterChdir, true
			case attached:
				return clusterDone, true
			}
			return clusterValue, true
		case strings.Contains(o.optional, l):
			return clusterDone, true
		case !strings.Contains(o.flags, l):
			return 0, false
		}
	}
	return clusterDone, true
}

// service reports whether this profile's native service is installed,
// from which profile file, and whether it runs. It only asks the service
// manager; it never changes the service.
func (d *Checkup) service(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, err := service.ResolveHost(ctx, d.Host)
	if err != nil {
		d.add("native service", StatusWarn, err.Error()+"; the service was not checked")
		return
	}
	s, err := service.NewSpec(d.Config, d.Source, d.State, host)
	if err != nil {
		d.add("native service", StatusFail, err.Error())
		return
	}
	info, err := os.Lstat(s.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		d.add("native service", StatusWarn, "not installed; CLI operation is still available")
		return
	case err != nil || !info.Mode().IsRegular():
		d.add("native service", StatusFail, "definition is unreadable or not a regular file")
		return
	}
	if raw, err := os.ReadFile(s.Path); err == nil && d.Source != "" {
		if source, found, err := service.DefinitionSource(raw); found && err == nil && source != d.Source && !fsx.SameFile(source, d.Source) {
			d.add("native service source", StatusWarn, "installed from "+source+", not this profile file")
		}
	}
	switch state, detail := serviceState(ctx, d.Runner, s); state {
	case serviceRunning:
		d.add("native service", StatusPass, "running")
	case serviceStopped:
		d.add("native service", StatusWarn, "installed, not started; run service start to activate it")
	default:
		hint := "inspect service status and logs"
		if s.ErrPath != "" {
			hint += " and " + s.ErrPath
		}
		d.add("native service", StatusFail, detail+"; "+hint)
	}
}

const (
	serviceRunning = "running"
	serviceStopped = "stopped" // installed but disabled, as install leaves it without --start
	serviceFailed  = "failed"  // enabled, or unknown, but not running
)

// serviceState asks the service manager whether s is running and, when it is
// not, whether it was deliberately left disabled.
func serviceState(ctx context.Context, runner proc.Runner, s service.Spec) (state, detail string) {
	if s.Platform == "darwin" {
		target := s.Domain + "/" + s.Label
		raw, err := runner.Run(ctx, "launchctl", []string{"print", target}, nil)
		switch {
		case err == nil && strings.Contains(string(raw), "state = running"):
			return serviceRunning, ""
		case err != nil && !service.LaunchdMissing(raw, err):
			return serviceFailed, "launchd did not report the job: " + err.Error()
		}
		raw, err = runner.Run(ctx, "launchctl", []string{"print-disabled", s.Domain}, nil)
		if err != nil {
			return serviceFailed, "not running, and launchd overrides are unreadable: " + err.Error()
		}
		if launchdDisabled(raw, s.Label) {
			return serviceStopped, ""
		}
		return serviceFailed, "installed and enabled but not running"
	}
	raw, err := runner.Run(ctx, "systemctl", []string{"--user", "is-active", s.Label}, nil)
	_, exited := errors.AsType[*exec.ExitError](err)
	switch {
	case err == nil && strings.TrimSpace(string(raw)) == "active":
		return serviceRunning, ""
	case err != nil && !exited:
		return serviceFailed, "systemd did not report the unit: " + err.Error()
	}
	// is-enabled exits 1 for a disabled unit, so read its output either way.
	raw, err = runner.Run(ctx, "systemctl", []string{"--user", "is-enabled", s.Label}, nil)
	switch enabled := strings.TrimSpace(string(raw)); {
	case enabled == "disabled":
		return serviceStopped, ""
	case enabled == "" && err != nil:
		return serviceFailed, "not running, and systemd did not report the unit: " + err.Error()
	default:
		return serviceFailed, "installed (" + enabled + ") but not running"
	}
}

// launchdDisabled reports whether launchctl print-disabled lists label as
// disabled. macOS 13 and later print "=> disabled"; older releases "=> true".
func launchdDisabled(out []byte, label string) bool {
	for line := range strings.Lines(string(out)) {
		key, value, ok := strings.Cut(line, "=>")
		if ok && strings.Trim(strings.TrimSpace(key), `"`) == label {
			value = strings.TrimSpace(value)
			return value == "disabled" || value == "true"
		}
	}
	return false
}

// notifications checks for the desktop notification helper when
// notifications are enabled.
func (d *Checkup) notifications() {
	if d.Config.Notifications == nil || !d.Config.Notifications.Enabled {
		return
	}
	program, _, _ := engine.NotificationCommand(runtime.GOOS, "", "")
	if _, err := exec.LookPath(program); err != nil {
		d.add("desktop notifications", StatusWarn, "helper unavailable; action execution remains enabled")
	} else {
		d.add("desktop notifications", StatusPass, "helper available; OS permissions/desktop delivery are not tested")
	}
}

// azureAuthentication requests a CLI access token once per Azure CLI and
// subscription. It never prints the token or the CLI's output.
func (d *Checkup) azureAuthentication(ctx context.Context) {
	seen := map[string]bool{}
	for _, name := range config.ActionNames(d.Config) {
		a := d.Config.Actions[name]
		if a.Type != config.ActionAzure {
			continue
		}
		for _, t := range a.Targets {
			key := a.AzureCLI + "\x00" + t.Subscription
			if seen[key] {
				continue
			}
			seen[key] = true
			authCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			raw, err := d.Runner.Run(authCtx, a.AzureCLI, []string{"account", "get-access-token", "--subscription", t.Subscription, "--query", "{expiresOn:expiresOn}", "--output", "json", "--only-show-errors"}, nil)
			cancel()
			var expiry struct {
				ExpiresOn string `json:"expiresOn"`
			}
			if err == nil {
				err = json.Unmarshal(raw, &expiry)
				if expiry.ExpiresOn == "" {
					err = errors.New("missing token expiry")
				}
			}
			// Never echo token/error output from credential tooling.
			if err != nil {
				d.add("Azure authentication", StatusFail, "CLI token request failed; check az login for the selected subscription")
			} else {
				d.add("Azure authentication", StatusPass, "CLI token obtained; resource/write permissions were not tested")
			}
		}
	}
}

// probes runs each configured post-action check once.
func (d *Checkup) probes(ctx context.Context) {
	for _, name := range config.ActionNames(d.Config) {
		for _, check := range d.Config.Actions[name].Checks {
			if err := engine.Probe(ctx, check); err != nil {
				d.add(name+"/"+check.Name, StatusFail, err.Error())
			} else {
				d.add(name+"/"+check.Name, StatusPass, "reachable")
			}
		}
	}
}

// Print writes rows as JSON or as a table with one line per row.
func Print(w io.Writer, rows []Diagnosis, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%-4s  %-26s %s\n", r.Status, r.Name, oneLine(r.Detail)); err != nil {
			return err
		}
	}
	return nil
}

// oneLine joins a multi-line detail, such as an errors.Join result, with "; "
// so each diagnosis stays one table row.
func oneLine(s string) string {
	lines := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.Join(slices.DeleteFunc(lines, func(l string) bool { return l == "" }), "; ")
}
