package engine

import (
	"slices"
	"testing"

	"github.com/rajasdevel/netshift/internal/config"
)

// A device-mode PostgreSQL rule is named per identity, so its profile may omit
// rule and bootstrap_ip unless a legacy single-owner rule is configured.
func TestValidationOfDevicePostgresTargets(t *testing.T) {
	e, _ := deviceFixture(t)
	names := config.ActionNames(e.Config)
	if len(names) != 1 {
		t.Fatalf("fixture actions: %v", names)
	}
	name := names[0]
	pgIndex := slices.IndexFunc(e.Config.Actions[name].Targets, func(t config.Target) bool { return t.Kind == "postgres" })
	if pgIndex < 0 {
		t.Fatal("fixture has no PostgreSQL target")
	}
	where := name + "/" + e.Config.Actions[name].Targets[pgIndex].ID
	variant := func(f func(a *config.ActionConfig, pg *config.Target)) config.Config {
		c := e.Config
		a := c.Actions[name]
		devices := *a.Devices
		a.Devices = &devices
		a.Targets = slices.Clone(a.Targets)
		f(&a, &a.Targets[pgIndex])
		c.Actions = map[string]config.ActionConfig{name: a}
		return c
	}
	for label, test := range map[string]struct {
		c    config.Config
		want string
	}{
		"without rule": {variant(func(a *config.ActionConfig, pg *config.Target) {
			a.Devices.LegacyTag, a.Devices.LegacyIdentity = "", ""
			pg.Rule = ""
		}), ""},
		"legacy without rule": {variant(func(a *config.ActionConfig, pg *config.Target) {
			a.Devices.LegacyTag, a.Devices.LegacyIdentity = "netshift.legacy.ip-history", "sam@laptop"
			pg.Rule = ""
		}),
			where + ": explicit subscription UUID, resource group, and rule required"},
		"private bootstrap": {variant(func(a *config.ActionConfig, pg *config.Target) { pg.BootstrapIP = "10.0.0.1" }),
			where + ` bootstrap_ip: not a public IPv4 address: "10.0.0.1"`},
		"empty bootstrap": {variant(func(a *config.ActionConfig, pg *config.Target) { pg.BootstrapIP = "" }), ""},
	} {
		if got := errorText(test.c.Validate()); got != test.want {
			t.Errorf("%s: got %q, want %q", label, got, test.want)
		}
	}
}

// errorText is err's message, or "" for nil.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
