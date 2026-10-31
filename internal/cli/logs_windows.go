//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/service"
)

// readNativeLog prints this profile's event log file, or --file. Windows has
// no tail and no journal, so NetShift reads the file itself.
func readNativeLog(ctx context.Context, c config.Config, state string, o *logsOptions) error {
	path := o.file
	if path == "" {
		s, err := service.NewSpec(c, "", state, service.CurrentHost())
		if err != nil {
			return err
		}
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
	return readFileLog(ctx, path, o.lines, o.follow, o.json, followPoll)
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
