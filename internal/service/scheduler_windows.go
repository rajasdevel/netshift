//go:build windows

package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

// On Windows the service is a per-user Task Scheduler task in the root
// folder, named after the profile. It runs only while the user is logged on
// (InteractiveToken), with the user's own rights, so creating it needs no
// administrator and the watcher can reach the user's Azure CLI sign-in and
// desktop. NetShift writes the task XML to Spec.Path and registers that file
// with schtasks.exe, which is part of Windows.
//
// Task Scheduler's own restart setting covers only a task that fails to
// launch, not a program that exits with an error. So besides starting at
// logon, the task is triggered every minute; with MultipleInstancesPolicy
// IgnoreNew a trigger does nothing while the watcher runs, and starts it
// again when it has stopped. Disabling the task stops both triggers.

// schtasks runs one Task Scheduler command with the schtasks.exe in the
// system directory, never one found through PATH.
func schtasks(ctx context.Context, runner proc.Runner, args ...string) ([]byte, error) {
	program, err := proc.SystemProgram("schtasks.exe")
	if err != nil {
		return nil, err
	}
	return runner.Run(ctx, program, args, nil)
}

// taskRunning is SCHED_S_TASK_RUNNING, the "Last Result" Task Scheduler
// reports while an instance runs. Unlike the status text, it is not
// translated.
const taskRunning = 0x41301

// taskPath is the Task Scheduler path of s's task, \NetShift\SID\PROFILE:
// a folder per account, so two accounts' profiles of the same name never
// share a task (see platformSpec).
func taskPath(s Spec) string { return s.Label }

// renderTask writes the task XML that runs args as the current user. It
// refuses values Task Scheduler would change: it expands %VARIABLE% in the
// command, arguments, and working directory. Environment is not carried:
// a task runs with the user's saved environment, not the installing shell's.
func renderTask(s Spec, args []string) ([]byte, error) {
	userSID, _, err := currentUser()
	if err != nil || userSID == "" {
		return nil, fmt.Errorf("cannot write the scheduled task: the user's security identifier is unknown: %v", err)
	}
	var bad error
	text := func(v string) string {
		escaped, err := xmlText(v)
		if err == nil && strings.Contains(v, "%") {
			err = fmt.Errorf("%q contains %%, which Task Scheduler expands", v)
		}
		if err != nil && bad == nil {
			bad = err
		}
		return escaped
	}
	quoted := make([]string, len(args)-1)
	for i, arg := range args[1:] {
		quoted[i] = proc.WindowsArg(arg)
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!-- " + managedMarker + " -->\n")
	if s.Source != "" {
		// encodeSource never leaves "--", which XML comments cannot contain.
		b.WriteString("<!-- " + SourceMarker + encodeSource(s.Source) + " -->\n")
		if _, err := xmlText(s.Source); err != nil {
			bad = err
		}
	}
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	b.WriteString("  <RegistrationInfo>\n    <Description>NetShift network events (" + text(s.Label) + ")</Description>\n  </RegistrationInfo>\n")
	sid := text(userSID)
	b.WriteString("  <Triggers>\n")
	b.WriteString("    <LogonTrigger>\n      <UserId>" + sid + "</UserId>\n    </LogonTrigger>\n")
	// A start boundary in the past repeats from now on.
	b.WriteString("    <TimeTrigger>\n      <StartBoundary>2000-01-01T00:00:00</StartBoundary>\n" +
		"      <Repetition>\n        <Interval>PT1M</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>\n      </Repetition>\n    </TimeTrigger>\n")
	b.WriteString("  </Triggers>\n")
	b.WriteString("  <Principals>\n    <Principal id=\"Author\">\n      <UserId>" + sid + "</UserId>\n" +
		"      <LogonType>InteractiveToken</LogonType>\n      <RunLevel>LeastPrivilege</RunLevel>\n    </Principal>\n  </Principals>\n")
	// Every limit Task Scheduler applies by default is lifted: the watcher
	// runs on battery, without a time limit, and at normal priority
	// (Priority 5), so the Azure CLI it starts is not throttled either.
	b.WriteString("  <Settings>\n" +
		"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n" +
		"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n" +
		"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n" +
		"    <AllowHardTerminate>true</AllowHardTerminate>\n" +
		"    <StartWhenAvailable>false</StartWhenAvailable>\n" +
		"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n" +
		"    <IdleSettings>\n      <StopOnIdleEnd>false</StopOnIdleEnd>\n      <RestartOnIdle>false</RestartOnIdle>\n    </IdleSettings>\n" +
		"    <AllowStartOnDemand>true</AllowStartOnDemand>\n" +
		"    <Hidden>false</Hidden>\n" +
		"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n" +
		"    <WakeToRun>false</WakeToRun>\n" +
		"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n" +
		"    <Priority>5</Priority>\n" +
		"    <RestartOnFailure>\n      <Interval>PT1M</Interval>\n      <Count>999</Count>\n    </RestartOnFailure>\n" +
		"  </Settings>\n")
	b.WriteString("  <Actions Context=\"Author\">\n    <Exec>\n")
	b.WriteString("      <Command>" + text(args[0]) + "</Command>\n")
	b.WriteString("      <Arguments>" + text(strings.Join(quoted, " ")) + "</Arguments>\n")
	if s.Home != "" {
		b.WriteString("      <WorkingDirectory>" + text(s.Home) + "</WorkingDirectory>\n")
	}
	b.WriteString("    </Exec>\n  </Actions>\n</Task>\n")
	if bad != nil {
		return nil, fmt.Errorf("cannot write the scheduled task: %w", bad)
	}
	return []byte(b.String()), nil
}

// registrationXML returns the definition as schtasks /Create /XML reads it:
// UTF-16 with a byte order mark. A task registered for install without
// --start is disabled from the start, so no trigger can run it.
func registrationXML(definition []byte, enabled bool) ([]byte, error) {
	text := string(definition)
	declaration := `<?xml version="1.0" encoding="UTF-8"?>`
	if !strings.HasPrefix(text, declaration) || !utf8.ValidString(text) {
		return nil, errors.New("the scheduled task definition is not NetShift's UTF-8 task XML")
	}
	text = `<?xml version="1.0" encoding="UTF-16"?>` + strings.TrimPrefix(text, declaration)
	if !enabled {
		// Settings is an unordered group, so the element may come first.
		text = strings.Replace(text, "<Settings>\n", "<Settings>\n    <Enabled>false</Enabled>\n", 1)
	}
	units := utf16.Encode([]rune(strings.ReplaceAll(text, "\n", "\r\n")))
	out := make([]byte, 2, 2+2*len(units))
	out[0], out[1] = 0xFF, 0xFE
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out, nil
}

// consoleText returns schtasks output as text. It writes in the console's
// code page, or UTF-16 for some queries; NetShift only looks for ASCII in it.
func consoleText(raw []byte) string {
	if len(raw) >= 2 && (raw[0] == 0xFF && raw[1] == 0xFE || len(raw)%2 == 0 && bytes.Count(raw, []byte{0})*3 > len(raw)) {
		raw = bytes.TrimPrefix(raw, []byte{0xFF, 0xFE})
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
		}
		return string(utf16.Decode(units))
	}
	return string(raw)
}

// TaskState is what Task Scheduler says about a profile's task.
type TaskState struct {
	Registered, Enabled, Running bool
	Owner                        string // the principal's UserId: a SID or DOMAIN\user
}

// QueryTask asks Task Scheduler about s's task. Only a definite answer
// counts: a task is unregistered only when the full task list lacks it.
func QueryTask(ctx context.Context, runner proc.Runner, s Spec) (TaskState, error) {
	name := taskPath(s)
	raw, err := schtasks(ctx, runner, "/Query", "/TN", name, "/XML")
	if err != nil {
		list, listErr := schtasks(ctx, runner, "/Query", "/FO", "CSV", "/NH")
		if listErr != nil {
			return TaskState{}, fmt.Errorf("cannot tell whether task %s exists: %w", name, errors.Join(err, listErr))
		}
		if found, parseErr := listsTask(consoleText(list), name); parseErr != nil || found {
			return TaskState{}, fmt.Errorf("cannot read task %s: %w", name, errors.Join(err, parseErr))
		}
		return TaskState{}, nil
	}
	document := consoleText(raw)
	state := TaskState{Registered: true, Enabled: taskEnabled(document), Owner: taskOwner(document)}
	raw, err = schtasks(ctx, runner, "/Query", "/TN", name, "/FO", "CSV", "/NH", "/V")
	if err != nil {
		return state, fmt.Errorf("cannot tell whether task %s runs: %w", name, err)
	}
	if state.Running, err = lastResultRunning(consoleText(raw), name); err != nil {
		return state, fmt.Errorf("cannot tell whether task %s runs: %w", name, err)
	}
	return state, nil
}

// listsTask reports whether schtasks /Query /FO CSV /NH output, which lists
// every task the user can see, names the task at path.
func listsTask(out, path string) (bool, error) {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if len(row) > 0 && strings.EqualFold(row[0], path) {
			return true, nil
		}
	}
}

// taskEnabled reports whether exported task XML leaves the task enabled:
// Settings has no <Enabled>false</Enabled>. Triggers have their own
// Enabled elements, which NetShift's task does not use.
func taskEnabled(document string) bool {
	_, settings, _ := strings.Cut(document, "<Settings>")
	settings, _, _ = strings.Cut(settings, "</Settings>")
	return !strings.Contains(settings, "<Enabled>false</Enabled>")
}

// taskOwner returns the UserId of the principal in exported task XML, or ""
// when it names none.
func taskOwner(document string) string {
	_, principals, _ := strings.Cut(document, "<Principals>")
	principals, _, _ = strings.Cut(principals, "</Principals>")
	_, id, found := strings.Cut(principals, "<UserId>")
	id, _, closed := strings.Cut(id, "</UserId>")
	if !found || !closed {
		return ""
	}
	return strings.TrimSpace(id)
}

// checkOwner refuses to act on a registered task that runs as another
// account. Only the account a task runs as may change it, even when an
// administrator could.
func checkOwner(s Spec, state TaskState) error {
	if !state.Registered {
		return nil
	}
	sid, name, err := currentUser()
	if err != nil {
		return fmt.Errorf("cannot tell whether task %s is yours: %w", taskPath(s), err)
	}
	if state.Owner != "" && (strings.EqualFold(state.Owner, sid) || name != "" && strings.EqualFold(state.Owner, name)) {
		return nil
	}
	owner := state.Owner
	if owner == "" {
		owner = "an unknown account"
	}
	return fmt.Errorf("refusing to change task %s: it runs as %s, not as you (%s)", taskPath(s), owner, sid)
}

// lastResultRunning reads schtasks /Query /TN path /FO CSV /NH /V, one row
// per trigger: host, task name, next run time, status, logon mode, last run
// time, last result, and so on. The task runs when the last result is
// SCHED_S_TASK_RUNNING. Any other shape is an error, not "stopped".
func lastResultRunning(out, path string) (bool, error) {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return false, err
	}
	running, matched := false, false
	for _, row := range rows {
		if len(row) < 7 || !strings.EqualFold(row[1], path) {
			continue
		}
		code, err := strconv.ParseInt(strings.TrimSpace(row[6]), 10, 64)
		if err != nil {
			return false, fmt.Errorf("unexpected last result %q", row[6])
		}
		matched = true
		running = running || code == taskRunning
	}
	if !matched {
		return false, errors.New("schtasks did not report the task")
	}
	return running, nil
}

// registerTask registers the definition as s's task, replacing an existing
// one, enabled or disabled. schtasks reads the XML from a file beside the
// definition, which is removed afterwards.
func registerTask(ctx context.Context, runner proc.Runner, s Spec, definition []byte, enabled bool) error {
	data, err := registrationXML(definition, enabled)
	if err != nil {
		return err
	}
	// /Create /F replaces a task; never another account's.
	state, err := QueryTask(ctx, runner, s)
	if err == nil {
		err = checkOwner(s, state)
	}
	if err != nil {
		return err
	}
	file := strings.TrimSuffix(s.Path, filepath.Ext(s.Path)) + ".register.xml"
	if err = fsx.AtomicWrite(file, data, 0600); err != nil {
		return err
	}
	defer os.Remove(file)
	_, err = schtasks(ctx, runner, "/Create", "/TN", taskPath(s), "/XML", file, "/F")
	return err
}

// Polling bounds for a task's instance to end after schtasks /End.
const (
	taskEndTimeout = 10 * time.Second
	taskEndPoll    = 250 * time.Millisecond
)

// stopTask disables s's task, so no trigger starts it again, and ends its
// running instance, waiting boundedly until Task Scheduler reports that it
// ended. A task that is not registered needs nothing.
func stopTask(ctx context.Context, runner proc.Runner, s Spec) error {
	state, err := QueryTask(ctx, runner, s)
	if err != nil || !state.Registered {
		return err
	}
	if err = checkOwner(s, state); err != nil {
		return err
	}
	if state.Enabled {
		if _, err = schtasks(ctx, runner, "/Change", "/TN", taskPath(s), "/DISABLE"); err != nil {
			return err
		}
	}
	if !state.Running {
		return nil
	}
	_, endErr := schtasks(ctx, runner, "/End", "/TN", taskPath(s))
	ctx, cancel := context.WithTimeout(ctx, taskEndTimeout)
	defer cancel()
	for {
		state, err = QueryTask(ctx, runner, s)
		if err == nil && !state.Running {
			// ended; an /End error was transient
			return waitForStateLock(ctx, s.State)
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return errors.Join(endErr, err)
			}
			return errors.Join(endErr, fmt.Errorf("task %s still runs after schtasks /End: %w", taskPath(s), ctx.Err()))
		case <-time.After(taskEndPoll):
		}
	}
}

// waitForStateLock waits, boundedly, until no process holds the lock of
// the state file at path. Task Scheduler reports an ended task before
// Windows has finished ending its watcher and released the lock, and a
// watcher started meanwhile would find the profile locked and exit.
func waitForStateLock(ctx context.Context, path string) error {
	for {
		unlock, err := store.Lock(path)
		if err == nil {
			unlock()
			return nil
		}
		if !errors.Is(err, store.ErrLocked) {
			return nil // nothing holds it; Lock reports the file itself
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the ended watcher still holds %s.lock: %w", path, ctx.Err())
		case <-time.After(taskEndPoll):
		}
	}
}

// startTask enables s's task and runs it now. Running a task that already
// runs does nothing (IgnoreNew).
func startTask(ctx context.Context, runner proc.Runner, s Spec) ([]byte, error) {
	state, err := QueryTask(ctx, runner, s)
	if err != nil {
		return nil, err
	}
	if !state.Registered {
		return nil, fmt.Errorf("task %s is not registered; run service install", taskPath(s))
	}
	if err = checkOwner(s, state); err != nil {
		return nil, err
	}
	if _, err := schtasks(ctx, runner, "/Change", "/TN", taskPath(s), "/ENABLE"); err != nil {
		return nil, err
	}
	return schtasks(ctx, runner, "/Run", "/TN", taskPath(s))
}

// taskStatus prints Task Scheduler's description of s's task. Like launchctl
// print and systemctl status, it fails unless the watcher runs.
func taskStatus(ctx context.Context, runner proc.Runner, s Spec) ([]byte, error) {
	state, err := QueryTask(ctx, runner, s)
	if err != nil {
		return nil, err
	}
	if !state.Registered {
		return nil, fmt.Errorf("task %s is not registered", taskPath(s))
	}
	out, err := schtasks(ctx, runner, "/Query", "/TN", taskPath(s), "/V", "/FO", "LIST")
	if err != nil {
		return out, err
	}
	switch {
	case !state.Enabled:
		return out, fmt.Errorf("task %s is disabled", taskPath(s))
	case !state.Running:
		return out, fmt.Errorf("task %s is enabled but not running", taskPath(s))
	}
	return out, nil
}

// deleteTask unregisters s's task.
func deleteTask(ctx context.Context, runner proc.Runner, s Spec) error {
	_, err := schtasks(ctx, runner, "/Delete", "/TN", taskPath(s), "/F")
	return err
}

// currentUser returns the security identifier and DOMAIN\user name of the
// account NetShift runs as, which its tasks run as. Tests replace it.
var currentUser = func() (sid, name string, err error) {
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	return u.Uid, u.Username, nil // on Windows, Uid is the SID
}

// platformHost gives a Windows host its configuration directory:
// %LOCALAPPDATA%, which Task Scheduler gives the task too and which stays on
// this machine. A relative or missing value is not guessed.
func platformHost(h Host) Host {
	if h.GOOS != "windows" {
		return h
	}
	if d := h.Getenv("LOCALAPPDATA"); filepath.IsAbs(d) {
		h.ConfigDir = filepath.Clean(d)
	}
	return h
}

// platformSpec lays out a Windows service: everything under
// %LOCALAPPDATA%\NetShift, and the task named NetShift-PROFILE. A task
// cannot carry environment variables, so none are recorded.
func platformSpec(c config.Config, source, state string, host Host) (Spec, bool, error) {
	if host.GOOS != "windows" {
		return Spec{}, false, nil
	}
	s := Spec{Platform: host.GOOS, Source: source, State: state, Home: host.Home, Environment: map[string]string{}}
	if host.Home == "" || host.ConfigDir == "" {
		return s, true, errors.New("cannot determine the user's profile and local application data directories; check USERPROFILE and LOCALAPPDATA")
	}
	sid, _, err := currentUser()
	if err != nil || !strings.HasPrefix(sid, "S-1-") || strings.ContainsAny(sid, `\/`) {
		return s, true, fmt.Errorf("cannot determine this account's security identifier: %v", err)
	}
	base := filepath.Join(host.ConfigDir, "NetShift")
	s.Binary = filepath.Join(base, "bin", "netshift.exe")
	s.Config = filepath.Join(base, "profiles", c.Profile+".json")
	s.Label = `\NetShift\` + sid + `\` + c.Profile
	s.Path = filepath.Join(base, "tasks", c.Profile+".xml")
	s.LogPath = filepath.Join(base, "logs", c.Profile+".log")
	return s, true, nil
}

// platformRender writes the task XML of a Windows spec.
func platformRender(s Spec) ([]byte, bool, error) {
	if s.Platform != "windows" {
		return nil, false, nil
	}
	// --scheduled-task tells the watcher Task Scheduler started it, so it may
	// close the console window Windows opens for it.
	args := []string{s.Binary, "--scheduled-task", "--config", s.Config, "--state", s.State, "--log-file", s.LogPath, "watch", "--apply"}
	b, err := renderTask(s, args)
	return b, true, err
}

// platformControl starts, stops, or reports a Windows task.
func platformControl(ctx context.Context, runner proc.Runner, s Spec, operation string) ([]byte, bool, error) {
	if s.Platform != "windows" {
		return nil, false, nil
	}
	switch operation {
	case "start":
		out, err := startTask(ctx, runner, s)
		return out, true, err
	case "stop":
		return nil, true, stopTask(ctx, runner, s)
	case "status":
		out, err := taskStatus(ctx, runner, s)
		return out, true, err
	}
	return nil, true, errors.New("unknown service operation")
}

// platformLoaded reports whether a Windows task is registered.
func platformLoaded(ctx context.Context, runner proc.Runner, s Spec) (bool, bool, error) {
	if s.Platform != "windows" {
		return false, false, nil
	}
	state, err := QueryTask(ctx, runner, s)
	return state.Registered, true, err
}

// platformInstall installs a Windows task. Task Scheduler has no state in
// which a changed definition waits for the next start, and a running
// watcher keeps the installed binary open, so the task is stopped and
// disabled before anything is written, and registered last: disabled
// without --start, so that nothing runs, and otherwise enabled and started.
func platformInstall(ctx context.Context, s Spec, opts InstallOptions, host Host, runner proc.Runner, installed config.Config, definition []byte) (bool, error) {
	if s.Platform != "windows" {
		return false, nil
	}
	// A registered task whose definition is gone is not one this
	// installation wrote, or it lost its record; replacing it is a decision.
	state, err := QueryTask(ctx, runner, s)
	if err == nil {
		err = checkOwner(s, state)
	}
	if err != nil {
		return true, err
	}
	if _, statErr := os.Lstat(s.Path); state.Registered && errors.Is(statErr, os.ErrNotExist) && !opts.Replace {
		return true, fmt.Errorf("task %s is registered, but its definition %s is missing; add --replace to install over it", taskPath(s), s.Path)
	}
	if err := stopTask(ctx, runner, s); err != nil {
		return true, err
	}
	if err := writeTaskFiles(s, installed, definition, host.Executable); err != nil {
		return true, err
	}
	if err := registerTask(ctx, runner, s, definition, opts.Start); err != nil {
		return true, err
	}
	if opts.Start {
		_, err := startTask(ctx, runner, s)
		return true, err
	}
	return true, nil
}

// writeTaskFiles is writeServiceFiles for a task: the binary (see
// writeBinary), the profile, and the log directory, and the definition last,
// so it never names files that were not written.
func writeTaskFiles(s Spec, c config.Config, definition []byte, executable string) error {
	if executable == "" {
		return errors.New("cannot locate the running netshift executable")
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if err = writeBinary(s, binary); err != nil {
		return err
	}
	profile, err := config.JSON(c)
	if err != nil {
		return err
	}
	if err = fsx.AtomicWrite(s.Config, profile, 0600); err != nil {
		return err
	}
	if err = fsx.EnsureDir(filepath.Dir(s.LogPath)); err != nil {
		return err
	}
	return fsx.AtomicWrite(s.Path, definition, 0600)
}

// writeBinary writes the shared binary. Windows cannot replace an executable
// that runs, as another profile's watcher may; it can rename one. So an
// unchanged binary is left alone, and a changed one that cannot be replaced
// is first moved aside to a name that later installs remove once nothing
// runs it.
func writeBinary(s Spec, binary []byte) error {
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

// unregister removes a Windows task's registration before its definition
// file. The task may have been deleted in Task Scheduler already.
func unregister(ctx context.Context, runner proc.Runner, s Spec) error {
	if s.Platform != "windows" {
		return nil
	}
	state, err := QueryTask(ctx, runner, s)
	if err == nil && state.Registered {
		if err = checkOwner(s, state); err == nil {
			err = deleteTask(ctx, runner, s)
		}
	}
	return err
}
