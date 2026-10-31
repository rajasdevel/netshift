// Package proc runs external programs for NetShift: with a timeout, bounded
// output, no shell, and contained with everything they start (a process
// group on macOS and Linux, a Job Object on Windows), which is stopped when
// the program exits.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Runner runs one external program with extra environment entries and returns
// its standard output. Tests replace it with fakes; Exec is the real one.
type Runner interface {
	Run(ctx context.Context, program string, args, env []string) ([]byte, error)
}

// Limits for programs started by Exec.
const (
	defaultMaxOutput = 1 << 20         // standard output kept by default
	MaxStderr        = 64 << 10        // standard error kept for error detail
	maxErrorDetail   = 1600            // bytes of standard error in an error
	WaitDelay        = 3 * time.Second // bound for output after exit, and for exit after cancellation
)

// Exec is the Runner that starts real programs. Each program runs with
// literal arguments and no shell, contained in its own Group (stopped when it
// exits), from the user's home directory, with bounded captured output. On
// Windows a .cmd or .bat program runs through cmd.exe with arguments it
// cannot misread, and other arguments are refused (see batchCommandLine).
type Exec struct {
	// MaxOutput caps captured standard output in bytes; output beyond it is
	// an error. Zero or less selects defaultMaxOutput.
	MaxOutput int
}

// Group is a program and everything it starts: a process group on macOS and
// Linux, a Job Object on Windows. ContainProcess prepares one; Start starts
// the program inside it, and Stop ends whatever is left.
type Group struct {
	cmd *exec.Cmd
	sys groupSys // the platform's handle on the group
}

// Start starts the program inside its group. A program that cannot be
// contained is not left running.
func (g *Group) Start() error { return g.start() }

// Stop kills everything left in the group and releases it. It is safe after
// a failed Start and more than once.
func (g *Group) Stop() { g.stop() }

// LimitedBuffer keeps at most limit bytes and records whether more arrived.
// It deliberately does not embed bytes.Buffer: io.Copy would use an embedded
// ReadFrom and bypass the limit.
type LimitedBuffer struct {
	buf      bytes.Buffer
	Limit    int
	overflow bool
}

// Write keeps what fits and reports success for all of p, so the program is
// not stopped by a broken pipe; overflow records the loss.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.Limit - b.buf.Len(); n > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.buf.Write(p)
	return n, nil
}

// Bytes returns the kept output. It aliases the buffer, so it is valid only
// until the next Write.
func (b *LimitedBuffer) Bytes() []byte { return b.buf.Bytes() }

// String returns the kept output as a string.
func (b *LimitedBuffer) String() string { return b.buf.String() }

// Run starts program and waits for it. env entries are added to NetShift's
// own environment. Exceeding an output limit is an error even when the
// program succeeds; a failure includes the start of standard error.
//
// The program writes to pipes NetShift reads itself, so waiting ends when the
// program exits, even if a process it started in the background still holds
// them open. That leftover work is then stopped with the process group, which
// closes the pipes, and the output is drained within WaitDelay.
func (r Exec) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = workingDir()
	group := ContainProcess(cmd)
	defer group.Stop() // also after a failed start
	cmd.WaitDelay = WaitDelay
	if env != nil {
		// Environ includes PWD for cmd.Dir, which os.Environ would leave stale.
		cmd.Env = append(cmd.Environ(), env...)
	}
	limit := r.MaxOutput
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	stdout, stderr := &LimitedBuffer{Limit: limit}, &LimitedBuffer{Limit: MaxStderr}
	outputs, err := startOutputs(group, stdout, stderr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", program, ctx.Err())
		}
		return nil, fmt.Errorf("%s failed: %w", program, err)
	}
	err = cmd.Wait()
	// Programs must not leave work running after they exit; stop anything
	// still in the program's group so retries cannot accumulate it. On Unix
	// a PID cannot be reused while any member of its group is alive; the
	// window is microseconds. A Windows job is a handle, so it has none.
	group.Stop()
	readErr := outputs.drain(WaitDelay)
	switch {
	case err == nil && (errors.Is(readErr, os.ErrDeadlineExceeded) || errors.Is(readErr, os.ErrClosed)):
		return nil, fmt.Errorf("%s exited, but a process it started outside its process group kept its output open", program)
	case err == nil && readErr != nil:
		return nil, fmt.Errorf("%s: read output: %w", program, readErr)
	case err == nil && (stdout.overflow || stderr.overflow):
		return nil, fmt.Errorf("%s exceeded the output limit", program)
	case err == nil:
		return stdout.Bytes(), nil
	case ctx.Err() != nil:
		return stdout.Bytes(), fmt.Errorf("%s: %w", program, ctx.Err())
	case errors.Is(err, exec.ErrWaitDelay):
		return stdout.Bytes(), fmt.Errorf("%s exited, but its output stayed open for %v", program, WaitDelay)
	}
	message := strings.TrimSpace(stderr.String())
	if len(message) > maxErrorDetail {
		message = strings.ToValidUTF8(message[:maxErrorDetail], "") + "..."
	}
	return stdout.Bytes(), fmt.Errorf("%s failed: %w: %s", program, err, message)
}

// commandOutputs copies a started program's standard output and error from
// the read ends of their pipes into limited buffers.
type commandOutputs struct {
	pipes  [2]*os.File
	errs   [2]error // each copy's result; nil means it reached end of file
	copied sync.WaitGroup
}

// startOutputs starts the group's program with standard output and error
// connected to pipes, and starts copying them into stdout and stderr. Because
// the program gets *os.File pipe ends, os/exec copies nothing itself, and
// cmd.Wait returns as soon as the program exits.
func startOutputs(group *Group, stdout, stderr *LimitedBuffer) (*commandOutputs, error) {
	cmd := group.cmd
	o := &commandOutputs{}
	var writers [2]*os.File
	closeAll := func() {
		for i := range o.pipes {
			for _, f := range []*os.File{o.pipes[i], writers[i]} {
				if f != nil {
					_ = f.Close()
				}
			}
		}
	}
	for i := range o.pipes {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll()
			return nil, err
		}
		o.pipes[i], writers[i] = r, w
	}
	cmd.Stdout, cmd.Stderr = writers[0], writers[1]
	err := group.Start()
	// The program holds its own copies of the write ends. Closing these lets
	// the reads end once it, and everything that inherited them, has exited.
	for i := range writers {
		_ = writers[i].Close()
		writers[i] = nil
	}
	if err != nil {
		closeAll()
		return nil, err
	}
	for i, buffer := range []*LimitedBuffer{stdout, stderr} {
		o.copied.Go(func() { _, o.errs[i] = io.Copy(buffer, o.pipes[i]) })
	}
	return o, nil
}

// drain waits up to timeout for both pipes to reach end of file and closes
// them. Output read in time is kept. It returns nil when both pipes ended,
// and otherwise a read error: os.ErrDeadlineExceeded (or os.ErrClosed) when
// something still held a pipe open at the deadline.
func (o *commandOutputs) drain(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, r := range o.pipes {
		if r.SetReadDeadline(deadline) != nil {
			// Without deadline support, closing the pipe ends the read.
			defer time.AfterFunc(timeout, func() { _ = r.Close() }).Stop()
		}
	}
	o.copied.Wait()
	for _, r := range o.pipes {
		_ = r.Close()
	}
	return errors.Join(o.errs[:]...)
}

// workingDir returns the directory programs start in: the user's home, so a
// hook that uses relative paths behaves the same from the CLI, under launchd
// (which starts jobs in /), and under systemd (which starts user units in the
// home directory), and under Task Scheduler. When home is unknown, missing, or not a directory this
// process may enter, it returns "", and programs inherit NetShift's own
// working directory. The check matters because on Unix os.StartProcess skips
// its own directory check when SysProcAttr is set (see ContainProcess), and a bad
// directory would fail every program with a misleading "fork/exec PROGRAM:
// no such file or directory".
func workingDir() string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) || !searchableDir(home) {
		return ""
	}
	return home
}
