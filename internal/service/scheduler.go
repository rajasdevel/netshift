package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
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

// schtasksProgram runs Task Scheduler commands. It is in System32, which is
// always on PATH.
const schtasksProgram = "schtasks.exe"

// taskRunning is SCHED_S_TASK_RUNNING, the "Last Result" Task Scheduler
// reports while an instance runs. Unlike the status text, it is not
// translated.
const taskRunning = 0x41301

// taskPath is the Task Scheduler path of s's task.
func taskPath(s Spec) string { return `\` + s.Label }

// renderTask writes the task XML that runs args as the user s.UserSID. It
// refuses values Task Scheduler would change: it expands %VARIABLE% in the
// command, arguments, and working directory. Environment is not carried:
// a task runs with the user's saved environment, not the installing shell's.
func renderTask(s Spec, args []string) ([]byte, error) {
	if s.UserSID == "" {
		return nil, errors.New("cannot write the scheduled task: the user's security identifier is unknown")
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
		quoted[i] = windowsArg(arg)
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
	sid := text(s.UserSID)
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

// windowsArg quotes one argument the way the C runtime, and Go's own
// command-line parser, read it back (as syscall.EscapeArg does on Windows).
func windowsArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
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

// taskState is what Task Scheduler says about s's task.
type taskState struct {
	registered, enabled, running bool
}

// queryTask asks Task Scheduler about s's task. Only a definite answer
// counts: a task is unregistered only when the full task list lacks it.
func queryTask(ctx context.Context, runner proc.Runner, s Spec) (taskState, error) {
	name := taskPath(s)
	raw, err := runner.Run(ctx, schtasksProgram, []string{"/Query", "/TN", name, "/XML"}, nil)
	if err != nil {
		list, listErr := runner.Run(ctx, schtasksProgram, []string{"/Query", "/FO", "CSV", "/NH"}, nil)
		if listErr != nil {
			return taskState{}, fmt.Errorf("cannot tell whether task %s exists: %w", name, errors.Join(err, listErr))
		}
		if found, parseErr := listsTask(consoleText(list), name); parseErr != nil || found {
			return taskState{}, fmt.Errorf("cannot read task %s: %w", name, errors.Join(err, parseErr))
		}
		return taskState{}, nil
	}
	state := taskState{registered: true, enabled: taskEnabled(consoleText(raw))}
	raw, err = runner.Run(ctx, schtasksProgram, []string{"/Query", "/TN", name, "/FO", "CSV", "/NH", "/V"}, nil)
	if err != nil {
		return state, fmt.Errorf("cannot tell whether task %s runs: %w", name, err)
	}
	if state.running, err = lastResultRunning(consoleText(raw), name); err != nil {
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
	file := strings.TrimSuffix(s.Path, filepath.Ext(s.Path)) + ".register.xml"
	if err = fsx.AtomicWrite(file, data, 0600); err != nil {
		return err
	}
	defer os.Remove(file)
	_, err = runner.Run(ctx, schtasksProgram, []string{"/Create", "/TN", taskPath(s), "/XML", file, "/F"}, nil)
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
	state, err := queryTask(ctx, runner, s)
	if err != nil || !state.registered {
		return err
	}
	if state.enabled {
		if _, err = runner.Run(ctx, schtasksProgram, []string{"/Change", "/TN", taskPath(s), "/DISABLE"}, nil); err != nil {
			return err
		}
	}
	if !state.running {
		return nil
	}
	_, endErr := runner.Run(ctx, schtasksProgram, []string{"/End", "/TN", taskPath(s)}, nil)
	ctx, cancel := context.WithTimeout(ctx, taskEndTimeout)
	defer cancel()
	for {
		state, err = queryTask(ctx, runner, s)
		if err == nil && !state.running {
			return nil // ended; an /End error was transient
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

// startTask enables s's task and runs it now. Running a task that already
// runs does nothing (IgnoreNew).
func startTask(ctx context.Context, runner proc.Runner, s Spec) ([]byte, error) {
	if _, err := runner.Run(ctx, schtasksProgram, []string{"/Change", "/TN", taskPath(s), "/ENABLE"}, nil); err != nil {
		return nil, err
	}
	return runner.Run(ctx, schtasksProgram, []string{"/Run", "/TN", taskPath(s)}, nil)
}

// taskStatus prints Task Scheduler's description of s's task. Like launchctl
// print and systemctl status, it fails unless the watcher runs.
func taskStatus(ctx context.Context, runner proc.Runner, s Spec) ([]byte, error) {
	state, err := queryTask(ctx, runner, s)
	if err != nil {
		return nil, err
	}
	if !state.registered {
		return nil, fmt.Errorf("task %s is not registered", taskPath(s))
	}
	out, err := runner.Run(ctx, schtasksProgram, []string{"/Query", "/TN", taskPath(s), "/V", "/FO", "LIST"}, nil)
	if err != nil {
		return out, err
	}
	switch {
	case !state.enabled:
		return out, fmt.Errorf("task %s is disabled", taskPath(s))
	case !state.running:
		return out, fmt.Errorf("task %s is enabled but not running", taskPath(s))
	}
	return out, nil
}

// deleteTask unregisters s's task.
func deleteTask(ctx context.Context, runner proc.Runner, s Spec) error {
	_, err := runner.Run(ctx, schtasksProgram, []string{"/Delete", "/TN", taskPath(s), "/F"}, nil)
	return err
}
