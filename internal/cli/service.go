package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// serviceOptions are the service command's options.
type serviceOptions struct{ start, replace, apply bool }

// serviceCommandLine describes service.
func serviceCommandLine() (*cmdline.Line, *serviceOptions) {
	f := cmdline.New("service", "--config FILE service print | install [--start] [--replace] | start | stop | status | uninstall [--apply] [--replace]",
		"Manage only this profile's native user service. install leaves the service stopped and disabled unless --start is given.")
	var o serviceOptions
	f.BoolVar(&o.start, "start", false, "with install: enable and (re)start the service")
	f.BoolVar(&o.replace, "replace", false, "with install or uninstall: act on a service installed from a different profile file")
	f.BoolVar(&o.apply, "apply", false, "with uninstall: stop and remove the service definition")
	return f, &o
}

// handleService runs a service operation for this user on this machine.
func handleService(ctx context.Context, c config.Config, configPath, state string, args []string) error {
	return runService(ctx, c, configPath, state, args, service.CurrentHost(), proc.Exec{})
}

// runService runs one service operation for profile c, installed from
// configPath, on host. runner runs launchctl or systemctl.
func runService(ctx context.Context, c config.Config, configPath, state string, args []string, host service.Host, runner proc.Runner) error {
	f, o := serviceCommandLine()
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	if len(positional) != 1 || !slices.Contains(service.Operations, positional[0]) {
		return f.Errorf("expected one operation: %s", strings.Join(service.Operations, ", "))
	}
	operation := positional[0]
	if o.start && operation != "install" {
		return f.Errorf("--start is only valid with install")
	}
	if o.replace && operation != "install" && operation != "uninstall" {
		return f.Errorf("--replace is only valid with install or uninstall")
	}
	if o.apply && operation != "uninstall" {
		return f.Errorf("--apply is only valid with uninstall")
	}
	ctx, cancel := service.WithTimeout(ctx)
	defer cancel()
	if host, err = service.ResolveHost(ctx, host); err != nil {
		return err
	}
	s, err := service.NewSpec(c, configPath, state, host)
	if err != nil {
		return err
	}
	switch operation {
	case "print":
		b, err := service.Render(s)
		if err != nil {
			return err
		}
		_, err = runtimeOutput.Write(b)
		return err
	case "install":
		if err = service.Install(ctx, c, s, service.InstallOptions{Start: o.start, Replace: o.replace, Out: runtimeOutput}, host, runner); err != nil {
			return err
		}
		fmt.Fprintf(runtimeOutput, "Installed %s\nSource: %s\nProfile copy: %s\nState: %s\n", s.Path, s.Source, s.Config, s.State)
		if s.ErrPath != "" {
			fmt.Fprintf(runtimeOutput, "Crash log: %s\n", s.ErrPath)
		}
		if o.start {
			fmt.Fprintln(runtimeOutput, "Started: yes")
		} else {
			fmt.Fprintln(runtimeOutput, "Started: no. The service is installed but stopped and disabled; run service start to activate it.")
		}
		return nil
	case "uninstall":
		return service.Uninstall(ctx, runner, s, service.UninstallOptions{Apply: o.apply, Replace: o.replace, Out: runtimeOutput})
	default:
		b, err := service.Control(ctx, runner, s, operation)
		_, _ = runtimeOutput.Write(b)
		return err
	}
}
