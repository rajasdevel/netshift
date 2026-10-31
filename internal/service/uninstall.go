package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
)

// UninstallOptions are service uninstall's flags.
type UninstallOptions struct {
	Apply, Replace bool
	Out            io.Writer // receives the preview and the result
}

// Uninstall stops and removes only this profile's managed definition.
// The profile, shared binary, state/history, and cloud registrations stay.
// It refuses a definition installed from another profile file with the same
// profile name unless replace is set. Without apply it only describes what it
// would do.
func Uninstall(ctx context.Context, runner proc.Runner, s Spec, opts UninstallOptions) error {
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		loaded, err := serviceLoaded(ctx, runner, s)
		if err != nil {
			return err
		}
		if loaded {
			return errors.New("service is loaded without a definition; refusing to stop an unverified service")
		}
		fmt.Fprintln(opts.Out, "No installed service definition; nothing removed.")
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to remove a symlink or non-regular service definition")
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return err
	}
	if !bytes.Contains(raw, []byte(managedMarker)) || !bytes.Contains(raw, []byte(s.Label)) {
		return errors.New("refusing to remove an unmanaged or differently named service")
	}
	source, err := installedSource(raw, s, opts.Replace)
	if err != nil {
		return err
	}
	if !opts.Apply {
		if source != "" {
			fmt.Fprintf(opts.Out, "Installed from: %s\n", source)
		}
		fmt.Fprintf(opts.Out, "Would stop %s and remove %s. The profile, shared binary, state, history, and cloud registrations stay. Use --apply.\n", s.Label, s.Path)
		return nil
	}
	if _, err = Control(ctx, runner, s, "stop"); err != nil {
		return err
	}
	// Re-read after stop so an intervening replacement cannot be silently removed.
	current, err := os.ReadFile(s.Path)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, current) {
		return errors.New("service definition changed during uninstall; refusing removal")
	}
	if s.Platform == "windows" {
		// The task may have been deleted in Task Scheduler already.
		state, err := QueryTask(ctx, runner, s)
		if err == nil && state.Registered {
			err = deleteTask(ctx, runner, s)
		}
		if err != nil {
			return err
		}
	}
	if err = os.Remove(s.Path); err != nil {
		return err
	}
	if s.Platform == "linux" {
		if _, err = runner.Run(ctx, "systemctl", []string{"--user", "daemon-reload"}, nil); err != nil {
			return err
		}
	}
	fmt.Fprintln(opts.Out, "Service removed. The profile, shared binary, state, history, and cloud registrations stay.")
	return nil
}

// installedSource returns the profile file a definition records, or "" for
// a definition that does not record one. A different
// profile file with the same profile name, or an unreadable record, is
// refused unless replace is set.
func installedSource(definition []byte, s Spec, replace bool) (string, error) {
	source, found, err := DefinitionSource(definition)
	switch {
	case !found:
		return "", nil
	case err != nil:
		source = "an unrecognized profile path"
	case source == s.Source || fsx.SameFile(source, s.Source):
		return source, nil
	}
	if !replace {
		return "", fmt.Errorf("%s was installed from %s, not %s; profiles with the same name share one service; add --replace to uninstall it from this profile", s.Label, source, s.Source)
	}
	return source, nil
}
