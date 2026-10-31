package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/doctor"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// fakeRunner records every program it is asked to run and succeeds.
type fakeRunner struct{ calls [][]string }

func (f *fakeRunner) Run(_ context.Context, program string, args, _ []string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{program}, args...))
	return nil, nil
}

// featureProfile is a validated profile with one command action, "hook",
// and a runner that records the hooks it runs.
func featureProfile(t *testing.T) (config.Config, *fakeRunner) {
	t.Helper()
	c := config.Config{Version: 1, Profile: "features", Actions: map[string]config.ActionConfig{"hook": {Type: "command", Command: []string{"hook"}, On: []string{"ip_changed"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c, &fakeRunner{}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type stubObserver discovery.Observation

func (o stubObserver) Observe(context.Context, string) discovery.Observation {
	return discovery.Observation(o)
}

// confirmed is a verified, online observation of ip.
func confirmed(ip string) discovery.Observation {
	return discovery.Observation{IP: ip, Online: true, Verified: true}
}

// diagnose runs every doctor check for a synthetic Linux account with no
// service installed, beside the state file, so tests never read the real
// host's service definitions or ask its service manager.
func diagnose(ctx context.Context, c config.Config, state string, runner proc.Runner, observer discovery.Observer, azure, checks bool) []doctor.Diagnosis {
	home := filepath.Join(filepath.Dir(state), "home")
	host := service.Host{GOOS: "linux", UID: 501, Home: home, ConfigDir: filepath.Join(home, ".config"), Getenv: func(string) string { return "" }}
	d := doctor.Checkup{Config: c, State: state, Runner: runner, Observer: observer, Host: host, Azure: azure, Checks: checks}
	return d.Run(ctx)
}

func findRow(rows []doctor.Diagnosis, name string) doctor.Diagnosis {
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	return doctor.Diagnosis{}
}

// exampleData returns a shipped example profile. On Windows its Unix command
// becomes cmd.exe, so that it validates and resolves there too.
func exampleData(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "config", name))
	if err != nil {
		t.Fatal(err)
	}
	return portable(data)
}

// portable replaces the Unix programs in a test profile with cmd.exe on
// Windows.
func portable(profile []byte) []byte {
	if runtime.GOOS != "windows" {
		return profile
	}
	cmd, _ := json.Marshal(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	for _, program := range []string{`"/usr/bin/printenv"`, `"/usr/bin/true"`} {
		profile = bytes.ReplaceAll(profile, []byte(program), cmd)
	}
	return profile
}
