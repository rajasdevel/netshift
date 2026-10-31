package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/store"
)

// statusOptions are the status command's options.
type statusOptions struct{ json bool }

// statusCommandLine describes status.
func statusCommandLine() (*cmdline.Line, *statusOptions) {
	f := cmdline.New("status", "[--config FILE] status [--json]",
		"Show saved observations and action/retry state. Saved observations are not a live health check; use doctor for that.")
	var o statusOptions
	f.BoolVar(&o.json, "json", false, "print the saved state as JSON")
	return f, &o
}

// handleStatus prints the saved state of the profile, readable or as JSON.
func handleStatus(c config.Config, path string, args []string) error {
	f, o := statusCommandLine()
	if err := f.ParseNone(args); err != nil {
		return err
	}
	s, err := store.Load(path)
	if err != nil {
		return err
	}
	if o.json {
		raw, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(runtimeOutput, string(raw))
		return nil
	}
	printStatus(runtimeOutput, c, s)
	return nil
}

// readableTime formats t as RFC 3339, or "never" for the zero time.
func readableTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// printStatus writes the saved observations and each action's progress,
// retry, error, and check results.
func printStatus(out io.Writer, c config.Config, s *store.State) {
	connectivity := s.Connectivity
	if connectivity == "" {
		connectivity = "unknown"
	}
	ip := s.IP
	if ip == "" {
		ip = "not observed"
	}
	fmt.Fprintf(out, "Profile: %s\nConnectivity (saved): %s\nPublic IPv4: %s\n", c.Profile, connectivity, ip)
	if s.Identity != "" {
		fmt.Fprintf(out, "Identity: %s\n", s.Identity)
	}
	if s.LastObservationError != "" {
		fmt.Fprintf(out, "Discovery error: %q\n", s.LastObservationError)
	}
	for _, name := range config.ActionNames(c) {
		a := s.Actions[name]
		if a == nil {
			fmt.Fprintf(out, "\n%s: waiting for an event\n", name)
			continue
		}
		status := "idle"
		if a.Pending != nil {
			status = "pending action"
		}
		if a.Verification != nil {
			status = "pending verification (action already completed)"
		}
		if a.Retired {
			status = "retired"
		}
		fmt.Fprintf(out, "\n%s: %s\n  Last success: %s\n", name, status, readableTime(a.LastSuccess))
		if a.Pending != nil {
			fmt.Fprintf(out, "  Trigger: %s; attempts: %d\n", a.Pending.Type, a.Attempts)
		}
		if !a.RetryAt.IsZero() && a.Pending != nil {
			fmt.Fprintf(out, "  Next retry: %s\n", readableTime(a.RetryAt))
		}
		if a.LastError != "" {
			fmt.Fprintf(out, "  Error: %q\n", a.LastError)
		}
		for _, check := range a.LastChecks {
			result := "reachable"
			if !check.Reachable {
				result = "failed"
			}
			fmt.Fprintf(out, "  Check %s: %s (%s)\n", check.Name, result, readableTime(check.At))
		}
	}
	fmt.Fprintln(out, "\nSaved observations are not a live health check. Use doctor for a fresh diagnosis.")
}
