package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/doctor"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// doctorOptions are the doctor command's options.
type doctorOptions struct{ azure, checks, json bool }

// doctorCommandLine describes doctor.
func doctorCommandLine() (*cmdline.Line, *doctorOptions) {
	f := cmdline.New("doctor", "[--config FILE] doctor [--azure] [--checks] [--json]",
		"Diagnose this profile without running actions. Exits 1 when any check fails.")
	var o doctorOptions
	f.BoolVar(&o.azure, "azure", false, "also request a CLI access token for each configured subscription (never printed)")
	f.BoolVar(&o.checks, "checks", false, "also probe configured post-action targets")
	f.BoolVar(&o.json, "json", false, "machine-readable diagnostic results")
	return f, &o
}

// handleDoctor diagnoses the profile for this user and host, prints the
// results, and fails when any check fails.
func handleDoctor(ctx context.Context, c config.Config, configPath, state string, args []string, runner proc.Runner, observer discovery.Observer) error {
	return runDoctor(ctx, c, configPath, state, args, runner, observer, service.CurrentHost())
}

// runDoctor diagnoses profile c, loaded from configPath, on host. The table
// starts with the profile file, which NETSHIFT_CONFIG may have chosen; the
// JSON results leave it out, so results pasted into an issue do not show
// the user's home directory.
func runDoctor(ctx context.Context, c config.Config, configPath, state string, args []string, runner proc.Runner, observer discovery.Observer, host service.Host) error {
	f, o := doctorCommandLine()
	if err := f.ParseNone(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	d := doctor.Checkup{Config: c, Source: configPath, State: state, Runner: runner, Observer: observer, Host: host, Azure: o.azure, Checks: o.checks}
	rows := d.Run(ctx)
	if !o.json {
		fmt.Fprintf(runtimeOutput, "Profile file: %s\n", configPath)
	}
	if err := doctor.Print(runtimeOutput, rows, o.json); err != nil {
		return err
	}
	if slices.ContainsFunc(rows, func(r doctor.Diagnosis) bool { return r.Status == doctor.StatusFail }) {
		return errors.New("doctor found failures; no actions were executed")
	}
	return nil
}
