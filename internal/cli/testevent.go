package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

// EventPreview is what test-event shows for one subscribed action: the
// command and environment it would run with, without running it.
type EventPreview struct {
	Action       string               `json:"action"`
	Type         string               `json:"type"`
	Command      []string             `json:"command,omitempty"`
	Environment  []string             `json:"environment"`
	Checks       []config.CheckConfig `json:"checks,omitempty"`
	AzureTargets int                  `json:"azure_targets,omitempty"`
}

// testEvents are the events test-event can simulate.
var testEvents = []string{config.EventIPChanged, config.EventConnectivityLost, config.EventConnectivityRestored, config.EventInterfaceChanged, config.EventMonitorResumed}

// testEventOptions are the test-event command's options.
type testEventOptions struct {
	ip, previousIP, value, previousValue, action string
	apply                                        bool
}

// testEventCommandLine describes test-event.
func testEventCommandLine() (*cmdline.Line, *testEventOptions) {
	f := cmdline.New("test-event", "--config FILE test-event EVENT [--ip IP] [--previous-ip IP] [--value V] [--previous-value V] [--action NAME] [--apply]",
		"Preview an event for the actions that subscribe to it. EVENT is one of "+strings.Join(testEvents, ", ")+
			".\nThe preview runs nothing; --apply runs selected command hooks with synthetic event data and never Azure.")
	var o testEventOptions
	f.StringVar(&o.ip, "ip", "", "simulated public `IP`, as canonical IPv4 (required for ip_changed)")
	f.StringVar(&o.previousIP, "previous-ip", "", "previous simulated public `IP`")
	f.StringVar(&o.value, "value", "", "simulated local-source `VALUE`")
	f.StringVar(&o.previousValue, "previous-value", "", "previous simulated local-source `VALUE`")
	f.StringVar(&o.action, "action", "", "only the subscribed action `NAME`")
	f.BoolVar(&o.apply, "apply", false, "execute selected command hooks with synthetic event data; Azure is always refused")
	return f, &o
}

// handleTestEvent previews a synthetic event for the actions that subscribe
// to it. With --apply it runs the selected command hooks and their checks; it
// refuses an Azure action as a usage error, before running anything.
func handleTestEvent(ctx context.Context, c config.Config, args []string, runner proc.Runner) error {
	f, o := testEventCommandLine()
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	if len(positional) != 1 || !config.ValidEvent(positional[0]) {
		return f.Errorf("expected one event: %s", strings.Join(testEvents, ", "))
	}
	eventType := positional[0]
	if eventType == config.EventIPChanged && o.ip == "" {
		return f.Errorf("%s requires --ip", config.EventIPChanged)
	}
	for _, v := range []string{o.ip, o.previousIP} {
		if v != "" {
			if normal, err := config.PublicIPv4(v); err != nil || normal != v {
				return f.Errorf("event IPs must be canonical public IPv4: %q", v)
			}
		}
	}
	if len(o.value) > 4096 || len(o.previousValue) > 4096 {
		return f.Errorf("event values must be at most 4096 bytes")
	}
	if o.action != "" {
		if _, ok := c.Actions[o.action]; !ok {
			return f.Errorf("unknown action %q; this profile has %s", o.action, strings.Join(config.ActionNames(c), ", "))
		}
	}
	event := store.Event{Type: eventType, IP: o.ip, PreviousIP: o.previousIP, Source: "test-event", Value: o.value, PreviousValue: o.previousValue, Synthetic: true, At: time.Now().UTC()}
	previews := []EventPreview{}
	for _, name := range config.ActionNames(c) {
		a := c.Actions[name]
		if (o.action != "" && name != o.action) || !config.Listens(a, event.Type) {
			continue
		}
		if o.apply && a.Type != config.ActionCommand {
			return f.Errorf("--apply runs command actions only; select one with --action (Azure is never simulated)")
		}
		previews = append(previews, EventPreview{Action: name, Type: a.Type, Command: a.Command, Environment: engine.EventEnvironment(event), Checks: a.Checks, AzureTargets: len(a.Targets)})
	}
	if len(previews) == 0 {
		return errors.New("no selected action subscribes to this event")
	}
	raw, err := json.MarshalIndent(previews, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(runtimeOutput, string(raw))
	if !o.apply {
		return nil
	}
	for _, preview := range previews {
		a := c.Actions[preview.Action]
		actionCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSeconds)*time.Second)
		_, err := runner.Run(actionCtx, a.Command[0], a.Command[1:], preview.Environment)
		if err == nil {
			for _, check := range a.Checks {
				if err = engine.Probe(actionCtx, check); err != nil {
					break
				}
			}
		}
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", preview.Action, err)
		}
	}
	return nil
}
