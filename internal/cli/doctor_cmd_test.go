package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/doctor"
)

func TestDoctorServiceStates(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label}
			diagnoseWith := func(source string) []doctor.Diagnosis {
				d := doctor.Checkup{Config: c, Source: source, State: filepath.Join(host.Home, "state.json"), Runner: r, Observer: stubObserver(confirmed("8.8.8.8")), Host: host}
				return d.Run(context.Background())
			}
			if row := findRow(diagnoseWith(profile), "native service"); row.Status != doctor.StatusWarn || !strings.Contains(row.Detail, "not installed") {
				t.Fatalf("before install: %+v", row)
			}
			// The profile row names the file, which NETSHIFT_CONFIG may have chosen.
			if row := findRow(diagnoseWith(profile), "profile"); row.Status != doctor.StatusPass || row.Detail != profile+": schema and action definitions are valid" {
				t.Fatalf("profile row: %+v", row)
			}
			if err := runServiceArgs(t, c, profile, host, r, "install"); err != nil {
				t.Fatal(err)
			}
			installCalls := len(r.calls)
			defer func() {
				for _, call := range r.calls[installCalls:] {
					if !slices.Contains([]string{"print", "print-disabled", "is-active", "is-enabled"}, call[len(call)-2]) {
						t.Errorf("doctor changed the service: %q", call)
					}
				}
			}()
			if row := findRow(diagnoseWith(profile), "native service"); row.Status != doctor.StatusWarn || row.Detail != "installed, not started; run service start to activate it" {
				t.Fatalf("installed without --start: %+v", row)
			}
			r.disabled = false
			if row := findRow(diagnoseWith(profile), "native service"); row.Status != doctor.StatusFail || !strings.Contains(row.Detail, "not running") {
				t.Fatalf("enabled but stopped: %+v", row)
			}
			r.loaded = true
			rows := diagnoseWith(profile)
			if row := findRow(rows, "native service"); row.Status != doctor.StatusPass {
				t.Fatalf("running: %+v", row)
			}
			if findRow(rows, "native service source").Name != "" {
				t.Fatal("warned about the profile that installed the service")
			}
			if row := findRow(diagnoseWith(filepath.Join(t.TempDir(), "other.json")), "native service source"); row.Status != doctor.StatusWarn || !strings.Contains(row.Detail, profile) {
				t.Fatalf("another profile file: %+v", row)
			}
		})
	}
}

// A service manager that gives no definite answer is a failure, never
// "installed, not started".
func TestDoctorServiceManagerWithoutAnswer(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label}
			if err := runServiceArgs(t, c, profile, host, r, "install"); err != nil {
				t.Fatal(err)
			}
			r.answerErr = fmt.Errorf("%s: %w", goos, context.DeadlineExceeded)
			d := doctor.Checkup{Config: c, Source: profile, State: filepath.Join(host.Home, "state.json"), Runner: r, Observer: stubObserver(confirmed("8.8.8.8")), Host: host}
			if row := findRow(d.Run(t.Context()), "native service"); row.Status != doctor.StatusFail || !strings.Contains(row.Detail, "did not report") {
				t.Fatalf("%+v", row)
			}
		})
	}
	// Without the systemd manager's environment the unit path is unknown.
	c, profile, host := serviceFixture(t, "linux")
	host.ManagerEnvironment = func(context.Context) ([]byte, error) { return nil, errors.New("no user manager") }
	r := &serviceRunner{}
	d := doctor.Checkup{Config: c, Source: profile, State: filepath.Join(host.Home, "state.json"), Runner: r, Observer: stubObserver(confirmed("8.8.8.8")), Host: host}
	if row := findRow(d.Run(t.Context()), "native service"); row.Status != doctor.StatusWarn || !strings.Contains(row.Detail, "not checked") || len(r.calls) != 0 {
		t.Fatalf("%+v %q", row, r.calls)
	}
}
