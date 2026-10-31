package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
)

// credentialRunner fails every command with output that must stay private.
type credentialRunner struct{}

func (credentialRunner) Run(context.Context, string, []string, []string) ([]byte, error) {
	return nil, errors.New("PRIVATE_TOKEN_MUST_NOT_APPEAR")
}

func TestDoctorDoesNotPrintCredentialToolOutput(t *testing.T) {
	target := config.Target{ID: "x", Kind: "nsg", NSG: "x", Subscription: "00000000-0000-0000-0000-000000000001", ResourceGroup: "test-group",
		Rule: "managed-ip", BootstrapIP: "8.8.8.8", Destination: "10.0.0.1/32", Ports: []string{"22", "443"}, Priority: 1040}
	c := config.Config{Version: 1, Profile: "features", Actions: map[string]config.ActionConfig{
		"hook": {Type: "azure_allowlist", AzureCLI: "az", Targets: []config.Target{target}},
	}}
	rows := diagnose(t.Context(), c, filepath.Join(t.TempDir(), "state.json"), credentialRunner{}, stubObserver(confirmed("8.8.8.8")), true, false)
	b, _ := json.Marshal(rows)
	if bytes.Contains(b, []byte("PRIVATE_TOKEN")) {
		t.Fatal("credential output leaked")
	}
	found := false
	for _, r := range rows {
		if r.Name == "Azure authentication" && r.Status == "FAIL" {
			found = true
		}
	}
	if !found {
		t.Fatal(rows)
	}
}
