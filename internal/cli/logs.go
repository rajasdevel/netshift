package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// logCommand returns the program and arguments that print the last lines of
// an event log, and follow it when asked: tail for a file (the macOS service
// log or --file), journalctl for a Linux user unit, filtered to this user
// and this profile's unit.
func logCommand(s service.Spec, file string, lines int, follow bool) (string, []string) {
	if file != "" || s.Platform == "darwin" {
		if file == "" {
			file = s.LogPath
		}
		args := []string{"-n", strconv.Itoa(lines)}
		if follow {
			args = append(args, "-F")
		}
		return "tail", append(args, "--", file)
	}
	args := []string{"--no-pager", "--output=cat", "--lines", strconv.Itoa(lines), "_UID=" + strconv.Itoa(os.Getuid()), "_SYSTEMD_USER_UNIT=" + s.Label}
	if follow {
		args = append(args, "--follow")
	}
	return "journalctl", args
}

// prettyLog writes one event-log line: as is when raw, otherwise as its time,
// event, and known fields, or quoted when it is not a JSON record (such as
// the "netshift: ..." line of a failure).
func prettyLog(out io.Writer, line string, raw bool) {
	if raw {
		fmt.Fprintln(out, line)
		return
	}
	var row map[string]any
	if json.Unmarshal([]byte(line), &row) != nil {
		fmt.Fprintf(out, "%q\n", line)
		return
	}
	fmt.Fprintf(out, "%v  %v", row["time"], row["event"])
	for _, key := range []string{"action", "trigger", "kind", "ip", "previous_ip", "error", "retry_at", "source", "value"} {
		if v, ok := row[key]; ok && v != "" && v != nil {
			fmt.Fprintf(out, "  %s=%q", key, fmt.Sprint(v))
		}
	}
	fmt.Fprintln(out)
}

// logsOptions are the logs command's options.
type logsOptions struct {
	follow, json bool
	lines        int
	file         string
}

// logsCommandLine describes logs.
func logsCommandLine() (*cmdline.Line, *logsOptions) {
	f := cmdline.New("logs", "--config FILE logs [--follow] [--lines N] [--json] [--file FILE]",
		"Read this profile's event log: its log file on macOS, its user journal on Linux.")
	var o logsOptions
	f.BoolVar(&o.follow, "follow", false, "follow new events until interrupted")
	f.IntVar(&o.lines, "lines", 50, "show the last `N` events, 1..1000")
	f.BoolVar(&o.json, "json", false, "print raw JSON log records")
	f.StringVar(&o.file, "file", "", "read the event log `FILE` instead of the native service log")
	return f, &o
}

// handleLogs prints this profile's event log, with a time limit unless it
// follows the log until interrupted.
func handleLogs(ctx context.Context, c config.Config, state string, args []string) error {
	f, o := logsCommandLine()
	if err := f.ParseNone(args); err != nil {
		return err
	}
	if o.lines < 1 || o.lines > 1000 {
		return f.Errorf("--lines must be 1..1000")
	}
	if !o.follow {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	s := service.Spec{Platform: service.CurrentHost().GOOS}
	if o.file == "" {
		var err error
		if s, err = service.NewSpec(c, "", state, service.CurrentHost()); err != nil {
			return err
		}
	}
	if o.file != "" || s.Platform == "darwin" {
		path := o.file
		if path == "" {
			path = s.LogPath
		}
		info, err := os.Stat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("no event log yet at %s; the watcher has not written one", path)
		case err != nil:
			return err
		case !info.Mode().IsRegular():
			return errors.New("event log must be a regular file")
		}
	}
	program, argv := logCommand(s, o.file, o.lines, o.follow)
	return readLog(ctx, program, argv, o.json)
}

// readLog runs a bounded log reader and pretty-prints what it writes.
func readLog(ctx context.Context, program string, argv []string, raw bool) error {
	command := exec.CommandContext(ctx, program, argv...)
	group := proc.ContainProcess(command)
	defer group.Stop()
	command.WaitDelay = proc.WaitDelay
	stderr := &proc.LimitedBuffer{Limit: proc.MaxStderr}
	command.Stderr = stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err = group.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		prettyLog(runtimeOutput, scanner.Text(), raw)
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		_ = command.Cancel()
	}
	err = command.Wait()
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	}
	if scanErr != nil {
		return scanErr
	}
	if err != nil {
		return fmt.Errorf("log reader failed: %w: %s", err, stderr.String())
	}
	return nil
}
