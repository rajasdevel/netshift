package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/doctor"
	"github.com/rajasdevel/netshift/internal/proc"
)

func TestDNSRecipeUsesExistingCLIWithLiteralConfirmedIP(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv.json")
	// The stub records argv without talking to a provider.
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "CAPTURE_ARGS=" + capture, "NETSHIFT_IP=8.8.8.8"}
	// Hooks start in the home directory, so name the script by absolute path.
	script, err := filepath.Abs("../../recipes/route53-ddns.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (proc.Exec{}).Run(context.Background(), "/bin/sh", []string{script, "Z12345", "host.example.com"}, env); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(capture)
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	change := argValue(args, "--change-batch")
	var body map[string]any
	if json.Unmarshal([]byte(change), &body) != nil || !strings.Contains(change, `"Value":"8.8.8.8"`) {
		t.Fatal(change)
	}
	if _, err := (proc.Exec{}).Run(context.Background(), "/bin/sh", []string{script, "Z12345", `bad"name`}, env); err == nil {
		t.Fatal("unescaped record accepted")
	}
}
func TestWebhookRecipeUsesLiteralJSONAndHTTPS(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv.txt")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\n"
	_ = os.WriteFile(filepath.Join(dir, "curl"), []byte(stub), 0700)
	payload := `{"event":"ip_changed","literal":"$(do-not-run)"}`
	env := []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "CAPTURE_ARGS=" + capture, "NETSHIFT_EVENT_JSON=" + payload}
	script, err := filepath.Abs("../../recipes/webhook.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (proc.Exec{}).Run(context.Background(), "/bin/sh", []string{script, "https://example.com/hooks"}, env); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(capture)
	if !strings.Contains(string(data), payload) {
		t.Fatal("payload altered")
	}
	if _, err := (proc.Exec{}).Run(context.Background(), "/bin/sh", []string{script, "http://example.com/hooks"}, env); err == nil {
		t.Fatal("insecure webhook accepted")
	}
}

// The recipes ship placeholder script paths and values; doctor must fail on
// them until they are replaced, while the profiles still validate.
func TestDoctorFailsOnRecipePlaceholders(t *testing.T) {
	recipes, err := filepath.Glob("../../recipes/*.json")
	if err != nil || len(recipes) == 0 {
		t.Fatal(recipes, err)
	}
	for _, path := range recipes {
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(path, err)
		}
		failed := false
		for _, name := range config.ActionNames(c) {
			for _, p := range doctor.ArgumentProblems(c.Actions[name].Command, t.TempDir()) {
				failed = failed || p.Status == doctor.StatusFail && strings.Contains(p.Detail, "placeholder argument")
			}
		}
		if !failed {
			t.Errorf("%s: placeholders not flagged", path)
		}
	}
}
