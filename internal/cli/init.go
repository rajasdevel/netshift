package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/fsx"
	"github.com/rajasdevel/netshift/internal/proc"
)

// initKinds are the kinds of profile init writes.
var initKinds = []string{"azure", "command"}

// starterAction names the one action of the starter profile.
const starterAction = "my_network_hook"

// initOptions are the options init command reads; the rest are init azure's.
type initOptions struct{ profile, output string }

// initCommandLine describes both forms of init, for help init, completion,
// and parsing init command. It carries every init azure option, so help and
// completion show them, and reads --profile and --output itself, the only
// two that init command takes. init azure parses with package engine's line.
func initCommandLine() (*cmdline.Line, *initOptions) {
	azure, _ := engine.InitCommandLine()
	f := cmdline.New("init", azure.Synopsis()+"\ninit command --profile NAME --output FILE",
		"Write a new profile, never over an existing file. init azure generates one from selected existing Azure rules, which it only reads; init command writes a starter with one command action.")
	var o initOptions
	azure.VisitAll(func(fl *flag.Flag) {
		switch fl.Name {
		case "profile":
			// The state, history, lock, and service are named after the
			// profile, so init command needs a deliberate name.
			f.StringVar(&o.profile, fl.Name, "", "portable profile `NAME`: required by init command; init azure defaults to "+fl.DefValue)
		case "output":
			f.StringVar(&o.output, fl.Name, fl.DefValue, fl.Usage)
		default:
			f.Var(fl.Value, fl.Name, fl.Usage)
		}
	})
	return f, &o
}

// initFormLine returns the command line of the form args choose: package
// engine's own for init azure, so its usage and errors are unchanged, and
// the line of both forms otherwise.
func initFormLine(args []string) *cmdline.Line {
	f, _ := initCommandLine()
	if f.FirstArgument(args) == "azure" {
		azure, _ := engine.InitCommandLine()
		return azure
	}
	return f
}

// handleInit writes a new profile. init azure belongs to package engine,
// which parses its own options; init command writes the starter profile.
func handleInit(ctx context.Context, args []string, runner proc.Runner) error {
	f, o := initCommandLine()
	if f.FirstArgument(args) == "azure" {
		return engine.HandleInit(ctx, args, runner, runtimeOutput)
	}
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	if len(positional) == 0 || !slices.Contains(initKinds, positional[0]) {
		return f.Errorf(`expected "azure" or "command"`)
	}
	if len(positional) != 1 {
		return f.Errorf("unexpected arguments %q", positional[1:])
	}
	var azureOnly []string
	profileGiven := false
	f.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "profile":
			profileGiven = true
		case "output":
		default:
			azureOnly = append(azureOnly, "--"+fl.Name)
		}
	})
	if len(azureOnly) != 0 {
		return f.Errorf("%s: only init azure takes this; init command takes --profile and --output", strings.Join(azureOnly, ", "))
	}
	if !profileGiven || o.output == "" {
		return f.Errorf("needs --profile NAME and --output FILE")
	}
	// The check validate applies, reported as a usage error like init azure's.
	if !config.ProfileName.MatchString(o.profile) {
		return f.Errorf("--profile must be 1 to 64 lowercase letters, digits, '-', or '_', starting with a letter or digit: %q", o.profile)
	}
	raw, err := starterProfile(o.profile)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(o.output)
	if err != nil {
		return err
	}
	if err = fsx.WriteNew(path, raw); errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; choose a new path and review before replacing a profile", path)
	} else if err != nil {
		return err
	}
	quoted := cmdline.ShellQuote(path)
	fmt.Fprintf(runtimeOutput, `Created %s with one command action, %s, which prints the event variables it receives.
Replace its command with your own, then check the profile and preview an event; neither runs the hook:
  netshift --config %s validate
  netshift --config %s test-event ip_changed --ip 8.8.8.8
To leave out --config: export %s=%s
`, path, starterAction, quoted, quoted, configEnv, quoted)
	return nil
}

// starterProfile returns the profile init command writes: the command action
// of config/example.json under the profile name, with every monitor setting
// written out at its default so the profile shows what can be tuned. It is
// parsed back as validate would, so it always passes validate.
func starterProfile(name string) ([]byte, error) {
	c := config.Config{Version: 1, Profile: name, Actions: map[string]config.ActionConfig{
		starterAction: {
			Type:           config.ActionCommand,
			On:             []string{config.EventIPChanged, config.EventConnectivityLost, config.EventConnectivityRestored},
			TimeoutSeconds: 10,
			Command:        []string{"/usr/bin/printenv", "NETSHIFT_EVENT", "NETSHIFT_IP", "NETSHIFT_PREVIOUS_IP"},
		},
	}}
	if err := c.Validate(); err != nil { // fills in the monitor defaults
		return nil, err
	}
	raw, err := config.JSON(c)
	if err != nil {
		return nil, err
	}
	if _, err = config.Parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
