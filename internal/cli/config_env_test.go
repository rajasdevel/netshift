package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/service"
)

// TestMain clears NETSHIFT_CONFIG, so a developer's own setting cannot change
// which profile a test loads; tests that need it use t.Setenv.
func TestMain(m *testing.M) {
	os.Unsetenv(configEnv)
	os.Exit(m.Run())
}

// NETSHIFT_CONFIG supplies the profile when --config is absent, and output
// names the file it chose; an explicit --config wins.
func TestConfigEnvironmentIsTheDefaultProfile(t *testing.T) {
	profile := exampleProfile(t, "example.json")
	state := filepath.Join(t.TempDir(), "state.json")
	t.Setenv(configEnv, profile)
	out := captureOutput(t)
	if err := cli(t.Context(), []string{"--state", state, "validate"}); err != nil {
		t.Fatal(err)
	}
	if want := `Valid profile "example" in ` + profile + " with actions: my_network_hook.\n"; out.String() != want {
		t.Fatalf("validate printed %q, want %q", out, want)
	}

	// An explicit --config wins over a variable that names a missing file.
	t.Setenv(configEnv, filepath.Join(t.TempDir(), "missing.json"))
	out.Reset()
	if err := cli(t.Context(), []string{"--config", profile, "--state", state, "validate"}); err != nil || !strings.Contains(out.String(), " in "+profile+" ") {
		t.Fatalf("--config did not win: %v %q", err, out)
	}

	// Without --config, a profile that fails to load names the variable.
	err := cli(t.Context(), []string{"--state", state, "validate"})
	if err == nil || !strings.HasPrefix(err.Error(), configEnv+"=") || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("load error does not name %s: %v", configEnv, err)
	}
	if exitStatus(err, &bytes.Buffer{}) != 1 {
		t.Fatal("a missing profile is not an invalid command line")
	}
}

// A relative NETSHIFT_CONFIG is refused as an invalid invocation: it would
// name a different file, and record a different service source, in each
// directory. Without either, --config is required.
func TestConfigEnvironmentMustBeAbsolute(t *testing.T) {
	dir := t.TempDir()
	writeProfileCopy(t, filepath.Join(dir, "home.json"))
	t.Chdir(dir)
	for value, message := range map[string]string{
		"home.json":   `NETSHIFT_CONFIG must be an absolute path, not "home.json"`,
		"./home.json": `NETSHIFT_CONFIG must be an absolute path, not "./home.json"`,
		"":            "--config FILE is required, or set NETSHIFT_CONFIG",
	} {
		t.Setenv(configEnv, value)
		out := captureOutput(t)
		err := cli(t.Context(), []string{"validate"})
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || !strings.Contains(stderr.String(), message) || out.Len() != 0 {
			t.Errorf("%s=%q: %v\n%s", configEnv, value, err, stderr.String())
		}
	}
}

// Commands without a profile ignore NETSHIFT_CONFIG, even an unusable one,
// and init refuses only an explicit --config.
func TestConfigEnvironmentLeavesProfileFreeCommandsAlone(t *testing.T) {
	t.Setenv(configEnv, "relative.json")
	for _, args := range [][]string{{"help"}, {"help", "status"}, {"version"}, {"completion", "bash"}, {"status", "-h"}} {
		captureOutput(t)
		if err := cli(t.Context(), args); exitStatus(err, &bytes.Buffer{}) != 0 {
			t.Errorf("%q read %s: %v", args, configEnv, err)
		}
	}
	profile := exampleProfile(t, "example.json")
	t.Setenv(configEnv, profile)
	captureOutput(t)
	output := filepath.Join(t.TempDir(), "starter.json")
	if err := cli(t.Context(), []string{"init", "command", "--output", output}); err != nil {
		t.Fatalf("init refused because %s is set: %v", configEnv, err)
	}
	err := cli(t.Context(), []string{"--config", profile, "init", "command", "--output", output + ".2"})
	var bad *cmdline.UsageError
	if !errors.As(err, &bad) || !strings.Contains(bad.Message, "init uses --output") {
		t.Fatalf("explicit --config accepted by init: %v", err)
	}
}

// The service records the absolute profile path NETSHIFT_CONFIG chose, and
// the --replace guard still tells two such files apart.
func TestConfigEnvironmentServiceSourceAndReplaceGuard(t *testing.T) {
	// service print renders the definition that install writes, source and all.
	profile := exampleProfile(t, "example.json")
	t.Setenv(configEnv, profile)
	out := captureOutput(t)
	if err := cli(t.Context(), []string{"--state", filepath.Join(t.TempDir(), "state.json"), "service", "print"}); err != nil {
		t.Fatal(err)
	}
	source, found, err := service.DefinitionSource(out.Bytes())
	if err != nil || !found || source != profile {
		t.Fatalf("definition source %q (found %t, %v), want %s", source, found, err, profile)
	}

	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			out := captureOutput(t)
			c, first, host := serviceFixture(t, goos)
			s := specFor(t, c, first, host)
			install := func(env string, args ...string) error {
				t.Helper()
				t.Setenv(configEnv, env)
				path, err := profilePath("", validateCommandLine())
				if err != nil {
					t.Fatal(err)
				}
				return runServiceArgs(t, c, path, host, &serviceRunner{label: s.Label}, append([]string{"install"}, args...)...)
			}
			if err := install(first); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Source: "+first+"\n") {
				t.Fatalf("install did not show the profile path:\n%s", out)
			}
			second := filepath.Join(t.TempDir(), "home.json")
			writeProfileCopy(t, second)
			if err := install(second); err == nil || !strings.Contains(err.Error(), "--replace") || !strings.Contains(err.Error(), first) {
				t.Fatalf("took over the service installed from %s: %v", first, err)
			}
			if err := install(second, "--replace"); err != nil {
				t.Fatal(err)
			}
			definition, _ := os.ReadFile(s.Path)
			if source, _, _ := service.DefinitionSource(definition); source != second {
				t.Fatalf("source %q after --replace, want %s", source, second)
			}
		})
	}
}
