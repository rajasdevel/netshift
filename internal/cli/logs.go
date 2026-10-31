package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
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
		"Read this profile's event log: its log file on macOS and Windows, its user journal on Linux.")
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
	if o.file != "" || s.Platform == "darwin" || s.Platform == "windows" {
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
	if s.Platform == "windows" {
		path := o.file
		if path == "" {
			path = s.LogPath
		}
		return readFileLog(ctx, path, o.lines, o.follow, o.json, followPoll)
	}
	program, argv := logCommand(s, o.file, o.lines, o.follow)
	return readLog(ctx, program, argv, o.json)
}

// Bounds of readFileLog.
const (
	followPoll = 500 * time.Millisecond
	tailWindow = 4 << 20 // bytes read from the end of the file for its last lines
	maxLine    = 1 << 20 // longest line kept, as the macOS and Linux readers keep
)

// readFileLog prints the last lines of the log file at path, as tail -n
// does, and with follow then prints what is appended until ctx ends,
// following the file across rotation and truncation, as tail -F does.
// Windows has no tail, so NetShift reads the file itself there. Its handle
// shares delete access, so a follower never blocks the watcher's rotation.
func readFileLog(ctx context.Context, path string, lines int, follow, raw bool, poll time.Duration) error {
	f, err := fsx.OpenRead(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	start := max(0, info.Size()-tailWindow)
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, tailWindow))
	if err != nil {
		return err
	}
	if start > 0 { // the window began inside a line
		if _, rest, found := bytes.Cut(data, []byte("\n")); found {
			data = rest
		}
	}
	complete := data[:bytes.LastIndexByte(data, '\n')+1]
	partial := slices.Clone(data[len(complete):])
	last := strings.Split(strings.TrimSuffix(string(complete), "\n"), "\n")
	if len(complete) == 0 {
		last = nil
	}
	for _, line := range last[max(0, len(last)-lines):] {
		prettyLog(runtimeOutput, strings.TrimSuffix(line, "\r"), raw)
	}
	if !follow {
		return nil
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := followOnce(&f, path, buf, &partial, raw); err != nil {
			return err
		}
	}
}

// followOnce prints the complete lines appended to *f since the last call,
// then, once the old file is read to its end, switches *f to a new file at
// path, and reads that too.
func followOnce(f **os.File, path string, buf []byte, partial *[]byte, raw bool) error {
	for {
		// Print what was appended, line by line.
		for {
			n, err := (*f).Read(buf)
			*partial = append(*partial, buf[:n]...)
			for {
				line, rest, found := bytes.Cut(*partial, []byte("\n"))
				if !found {
					break
				}
				prettyLog(runtimeOutput, strings.TrimSuffix(string(line), "\r"), raw)
				*partial = rest
			}
			if len(*partial) > maxLine {
				*partial = (*partial)[:0] // an overlong line is dropped
			}
			if n == 0 || err != nil {
				break
			}
		}
		current, err := os.Stat(path)
		if err != nil {
			return nil // between rotation's rename and the next write
		}
		opened, err := (*f).Stat()
		if err != nil {
			return err
		}
		if os.SameFile(opened, current) {
			if offset, err := (*f).Seek(0, io.SeekCurrent); err == nil && current.Size() < offset {
				_, _ = (*f).Seek(0, io.SeekStart) // truncated
				*partial = (*partial)[:0]
			}
			return nil
		}
		next, err := fsx.OpenRead(path)
		if err != nil {
			return nil // try again at the next poll
		}
		(*f).Close()
		*f, *partial = next, (*partial)[:0]
	}
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
