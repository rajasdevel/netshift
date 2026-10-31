package cli

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/cmdline"
)

func TestCLIUsageHelpAndFileGuards(t *testing.T) {
	captureOutput(t)
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profile, exampleData(t, "example.json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cli(t.Context(), nil); !errors.Is(err, cmdline.ErrUsage) {
		t.Fatalf("no arguments: %v", err)
	}
	if err := cli(t.Context(), []string{"frobnicate"}); !errors.Is(err, cmdline.ErrUsage) || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command: %v", err)
	}
	if err := cli(t.Context(), []string{"--config", profile, "status", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("subcommand help: %v", err)
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Link(profile, alias); err != nil {
		t.Fatal(err)
	}
	if err := cli(t.Context(), []string{"--config", profile, "--state", alias, "status"}); err == nil || !strings.Contains(err.Error(), "must not be the profile") {
		t.Fatalf("hard-linked state accepted: %v", err)
	}
}
