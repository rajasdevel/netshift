package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
)

// init command writes a private profile that passes validate and holds what
// config/example.json holds, under the chosen name.
func TestInitCommandWritesTheExampleProfile(t *testing.T) {
	out := captureOutput(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "home profile.json") // a missing directory, a name to quote
	if err := cli(t.Context(), []string{"init", "command", "--profile", "home", "--output", path}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("profile not private: %v %v", info, err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("the starter fails validate: %v", err)
	}
	want, err := config.Load("../../config/example.json")
	if err != nil {
		t.Fatal(err)
	}
	want.Profile = "home"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("starter differs from config/example.json:\n got %+v\nwant %+v", got, want)
	}
	quoted := cmdline.ShellQuote(path)
	for _, line := range []string{"Created " + path + " with one command action, my_network_hook",
		"netshift --config " + quoted + " validate\n", "export NETSHIFT_CONFIG=" + quoted + "\n"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	out.Reset()
	if err = cli(t.Context(), []string{"--config", path, "--state", filepath.Join(dir, "state.json"), "validate"}); err != nil {
		t.Fatal(err)
	}
	// Options may come before the form.
	path = filepath.Join(dir, "other.json")
	if err = cli(t.Context(), []string{"init", "--output", path, "--profile", "other", "command"}); err != nil {
		t.Fatal(err)
	}
	if c, err := config.Load(path); err != nil || c.Profile != "other" {
		t.Fatalf("profile: %q %v", c.Profile, err)
	}
}

// init command never replaces a file or writes through a link to one.
func TestInitCommandNeverOverwrites(t *testing.T) {
	captureOutput(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "home.json")
	if err := os.WriteFile(existing, []byte("mine"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(existing, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, link} {
		err := cli(t.Context(), []string{"init", "command", "--profile", "home", "--output", path})
		if err == nil || !strings.Contains(err.Error(), path+" already exists") || exitStatus(err, &bytes.Buffer{}) != 1 {
			t.Errorf("%s: %v", path, err)
		}
	}
	if data, _ := os.ReadFile(existing); string(data) != "mine" {
		t.Fatal("init command replaced a profile")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("a refused write left files behind: %v", entries)
	}
}

// Every invalid init command line exits 2, prints init's usage once, and
// writes nothing.
func TestInitCommandUsageErrors(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "p.json")
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"init", "command"}, "init: needs --profile NAME and --output FILE"},
		// The profile names the state, history, lock, and service, so a
		// starter never takes init azure's default name.
		{[]string{"init", "command", "--output", output}, "init: needs --profile NAME and --output FILE"},
		{[]string{"init", "command", "--profile", "home"}, "init: needs --profile NAME and --output FILE"},
		{[]string{"init", "command", "extra", "--profile", "home", "--output", output}, `init: unexpected arguments ["extra"]`},
		{[]string{"init", "commands", "--profile", "home", "--output", output}, `init: expected "azure" or "command"`},
		{[]string{"init", "command", "--profile", "home", "--output", output, "--subscription", "00000000-0000-0000-0000-000000000001"}, "init: --subscription: only init azure takes this"},
		{[]string{"init", "command", "--profile", "home", "--output", output, "--known-ip", "8.8.8.8", "--nsg-rule", "g/n/r"}, "init: --known-ip, --nsg-rule: only init azure takes this"},
		{[]string{"init", "command", "--output", output, "--profile", "Home"}, "init: --profile must be 1 to 64 lowercase"},
		{[]string{"init", "command", "--profile", "home", "--output", output, "--bogus"}, "init: flag provided but not defined: --bogus"},
		{[]string{"--state", filepath.Join(dir, "s.json"), "init", "command", "--profile", "home", "--output", output}, "init uses --output rather than --config/--state"},
	} {
		out := captureOutput(t)
		err := cli(t.Context(), tc.args)
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || strings.Count(stderr.String(), tc.message) != 1 || out.Len() != 0 {
			t.Errorf("%q: %v\n%s", tc.args, err, stderr.String())
		}
		if strings.Contains(tc.message, "init:") && strings.Count(stderr.String(), "init command --profile NAME --output FILE") != 1 {
			t.Errorf("%q: usage not printed once:\n%s", tc.args, stderr.String())
		}
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused command line wrote the profile")
	}
}

// init azure keeps its own command line: its errors and -h print only its
// own usage, as in 0.6.0, wherever the form comes among the options.
func TestInitAzureIsUnchanged(t *testing.T) {
	output := filepath.Join(t.TempDir(), "p.json")
	for _, args := range [][]string{
		{"init", "azure", "--output", output},
		{"init", "--output", output, "azure"},
		{"init", "azure", "--bogus"},
		{"init", "--profile", "work", "azure", "--known-ip"},
	} {
		err := cli(t.Context(), args)
		var stderr bytes.Buffer
		if exitStatus(err, &stderr) != 2 || !strings.Contains(stderr.String(), "Usage: netshift init azure --subscription UUID") || strings.Contains(stderr.String(), "init command") {
			t.Errorf("%q: %v\n%s", args, err, stderr.String())
		}
	}
	for _, args := range [][]string{{"init", "azure", "-h"}, {"help", "init"}} {
		out := captureOutput(t)
		err := cli(t.Context(), args)
		if exitStatus(err, &bytes.Buffer{}) != 0 {
			t.Fatalf("%q: %v", args, err)
		}
		if both := strings.Contains(out.String(), "\n       netshift init command --profile NAME --output FILE\n"); both != (args[0] == "help") {
			t.Errorf("%q: shows init command: %t\n%s", args, both, out)
		}
		if !strings.Contains(out.String(), "--profile NAME") || !strings.Contains(out.String(), "--output FILE") {
			t.Errorf("%q: options missing:\n%s", args, out)
		}
	}
}
