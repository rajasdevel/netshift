package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/fsx"
)

// fixtureTarget is a valid Azure target of kind "nsg" or "postgres".
func fixtureTarget(id, kind string) Target {
	t := Target{ID: id, Kind: kind, Subscription: "00000000-0000-0000-0000-000000000001", ResourceGroup: "test-group", Rule: "managed-ip", BootstrapIP: "8.8.8.8"}
	if kind == "nsg" {
		t.NSG = id
		t.Destination = "10.0.0.1/32"
		t.Ports = []string{"22", "443"}
		t.Priority = 1040
	} else {
		t.Server = id
	}
	return t
}

// validationCase builds one profile for TestValidationErrorsAreStable.
type validationCase struct {
	name  string
	build func() Config
}

func validationCases() []validationCase {
	cmd := func() ActionConfig { return ActionConfig{Type: "command", Command: []string{trueProgram()}} }
	base := func(actions map[string]ActionConfig) Config {
		return Config{Version: 1, Profile: "test", Actions: actions}
	}
	one := func(a ActionConfig) Config { return base(map[string]ActionConfig{"act": a}) }
	az := func(targets ...Target) ActionConfig { return ActionConfig{Type: "azure_allowlist", Targets: targets} }
	nsg := func(f func(*Target)) Target { t := fixtureTarget("one", "nsg"); f(&t); return t }
	pg := func(f func(*Target)) Target { t := fixtureTarget("db", "postgres"); f(&t); return t }
	mapped := func(f func(*Target)) Target {
		t := fixtureTarget("mapped", "nsg")
		t.SourceMode, t.KnownIPs, t.RuleShape = "replace_known", []string{"8.8.8.8"}, "aa0000000000000000000000000000000000000000000000000000000000000b"
		t.Destination, t.Ports, t.Priority, t.BootstrapIP = "", nil, 0, ""
		f(&t)
		return t
	}
	withMonitor := func(f func(*MonitorConfig)) func() Config {
		return func() Config { c := one(cmd()); f(&c.Monitor); return c }
	}
	return []validationCase{
		{"valid command", func() Config { return one(cmd()) }},
		{"valid nsg", func() Config { return one(az(nsg(func(*Target) {}))) }},
		{"valid postgres", func() Config { return one(az(pg(func(*Target) {}))) }},
		{"valid mapped", func() Config { return one(az(mapped(func(*Target) {}))) }},
		{"version", func() Config { c := one(cmd()); c.Version = 2; return c }},
		{"profile", func() Config { c := one(cmd()); c.Profile = "Bad"; return c }},
		{"known ip", func() Config { c := one(cmd()); c.KnownIPs = []string{"10.0.0.1"}; return c }},
		{"identity", func() Config { c := one(cmd()); c.Identity = "Sam@Laptop.local"; return c }},
		{"notifications", func() Config { c := one(cmd()); c.Notifications = &NotificationConfig{AfterFailures: 101}; return c }},
		{"notification cooldown", func() Config { c := one(cmd()); c.Notifications = &NotificationConfig{CooldownSeconds: 29}; return c }},
		{"resume", withMonitor(func(m *MonitorConfig) { m.ResumeAfterSeconds = 59 })},
		{"interval", withMonitor(func(m *MonitorConfig) { m.IntervalSeconds = 4 })},
		{"long interval", withMonitor(func(m *MonitorConfig) { m.IntervalSeconds = 86401 })},
		{"discovery timeout", withMonitor(func(m *MonitorConfig) { m.TimeoutSeconds = 61 })},
		{"confirmations", withMonitor(func(m *MonitorConfig) { m.Confirmations = 11 })},
		{"offline confirmations", withMonitor(func(m *MonitorConfig) { m.OfflineConfirmations = -1 })},
		{"retry", withMonitor(func(m *MonitorConfig) { m.RetrySeconds = 4 })},
		{"retry bounds", withMonitor(func(m *MonitorConfig) { m.RetrySeconds = 60; m.MaxRetrySeconds = 30 })},
		{"one source", withMonitor(func(m *MonitorConfig) { m.IPSources = []string{"https://a.example"} })},
		{"http source", withMonitor(func(m *MonitorConfig) { m.IPSources = []string{"http://a.example", "https://b.example"} })},
		{"same host", withMonitor(func(m *MonitorConfig) { m.IPSources = []string{"https://a.example/x", "https://A.example/y"} })},
		{"no actions", func() Config { return base(nil) }},
		{"action name", func() Config { return base(map[string]ActionConfig{"-bad": cmd()}) }},
		{"bad event", func() Config { a := cmd(); a.On = []string{"reconcile"}; return one(a) }},
		{"dup event", func() Config { a := cmd(); a.On = []string{"ip_changed", "ip_changed"}; return one(a) }},
		{"bad check", func() Config { a := cmd(); a.Checks = []CheckConfig{{Name: "x", Type: "udp"}}; return one(a) }},
		{"check timeout", func() Config {
			a := cmd()
			a.Checks = []CheckConfig{{Name: "x", Type: "tcp", TimeoutSeconds: 31}}
			return one(a)
		}},
		{"timeout", func() Config { a := cmd(); a.TimeoutSeconds = 1801; return one(a) }},
		{"type", func() Config { a := cmd(); a.Type = "shell"; return one(a) }},
		{"relative command", func() Config { a := cmd(); a.Command = []string{"bin/hook"}; return one(a) }},
		{"empty command", func() Config { a := cmd(); a.Command = []string{" "}; return one(a) }},
		{"command with targets", func() Config { a := cmd(); a.Targets = []Target{fixtureTarget("x", "nsg")}; return one(a) }},
		{"relative az", func() Config { a := az(nsg(func(*Target) {})); a.AzureCLI = "bin/az"; return one(a) }},
		{"az no targets", func() Config { return one(az()) }},
		{"az offline event", func() Config { a := az(nsg(func(*Target) {})); a.On = []string{"connectivity_lost"}; return one(a) }},
		{"az command", func() Config { a := az(nsg(func(*Target) {})); a.Command = []string{"x"}; return one(a) }},
		{"shared tag", func() Config {
			a := az(nsg(func(*Target) {}))
			a.SharedIPHistory = &SharedIPHistoryConfig{Tag: "other.tag"}
			return one(a)
		}},
		{"shared limit", func() Config {
			a := az(nsg(func(*Target) {}))
			a.SharedIPHistory = &SharedIPHistoryConfig{Limit: 11}
			return one(a)
		}},
		{"shared no nsg", func() Config {
			a := az(pg(func(*Target) {}))
			a.SharedIPHistory = &SharedIPHistoryConfig{}
			return one(a)
		}},
		{"devices with shared", func() Config {
			a := az(nsg(func(*Target) {}))
			a.SharedIPHistory = &SharedIPHistoryConfig{}
			a.Devices = &DevicesConfig{}
			return one(a)
		}},
		{"devices prefix", func() Config {
			a := az(nsg(func(*Target) {}))
			a.Devices = &DevicesConfig{TagPrefix: "other.device."}
			return one(a)
		}},
		{"devices history", func() Config {
			a := az(nsg(func(*Target) {}))
			a.Devices = &DevicesConfig{HistoryLimit: 4}
			return one(a)
		}},
		{"devices reconcile", func() Config {
			a := az(nsg(func(*Target) {}))
			a.Devices = &DevicesConfig{ReconcileSeconds: 59}
			return one(a)
		}},
		{"target id", func() Config { return one(az(nsg(func(t *Target) { t.ID = "-x" }))) }},
		{"dup target id", func() Config { return one(az(nsg(func(*Target) {}), pg(func(t *Target) { t.ID = "one" }))) }},
		{"subscription", func() Config { return one(az(nsg(func(t *Target) { t.Subscription = "sub" }))) }},
		{"resource group", func() Config { return one(az(nsg(func(t *Target) { t.ResourceGroup = " " }))) }},
		{"rule", func() Config { return one(az(nsg(func(t *Target) { t.Rule = "" }))) }},
		{"rule dash", func() Config { return one(az(nsg(func(t *Target) { t.Rule = "-x" }))) }},
		{"bootstrap missing", func() Config { return one(az(nsg(func(t *Target) { t.BootstrapIP = "" }))) }},
		{"bootstrap private", func() Config { return one(az(nsg(func(t *Target) { t.BootstrapIP = "10.1.1.1" }))) }},
		{"mapped bootstrap", func() Config { return one(az(mapped(func(t *Target) { t.BootstrapIP = "8.8.4.4" }))) }},
		{"mapped no known", func() Config { return one(az(mapped(func(t *Target) { t.KnownIPs = nil }))) }},
		{"mapped shape", func() Config { return one(az(mapped(func(t *Target) { t.RuleShape = "zz" + t.RuleShape[2:] }))) }},
		{"mapped known private", func() Config { return one(az(mapped(func(t *Target) { t.KnownIPs = []string{"10.0.0.1"} }))) }},
		{"mapped ports", func() Config { return one(az(mapped(func(t *Target) { t.Ports = []string{"22"} }))) }},
		{"nsg mode", func() Config { return one(az(nsg(func(t *Target) { t.SourceMode = "append" }))) }},
		{"nsg known", func() Config { return one(az(nsg(func(t *Target) { t.KnownIPs = []string{"8.8.8.8"} }))) }},
		{"nsg priority", func() Config { return one(az(nsg(func(t *Target) { t.Priority = 99 }))) }},
		{"nsg server", func() Config { return one(az(nsg(func(t *Target) { t.Server = "s" }))) }},
		{"nsg no ports", func() Config { return one(az(nsg(func(t *Target) { t.Ports = nil }))) }},
		{"nsg destination", func() Config { return one(az(nsg(func(t *Target) { t.Destination = "10.0.0.0/24" }))) }},
		{"nsg port", func() Config { return one(az(nsg(func(t *Target) { t.Ports = []string{"0"} }))) }},
		{"nsg dup port", func() Config { return one(az(nsg(func(t *Target) { t.Ports = []string{"22", "22"} }))) }},
		{"pg nsg", func() Config { return one(az(pg(func(t *Target) { t.NSG = "n" }))) }},
		{"pg no server", func() Config { return one(az(pg(func(t *Target) { t.Server = "" }))) }},
		{"kind", func() Config { return one(az(nsg(func(t *Target) { t.Kind = "vm" }))) }},
		{"dup resource", func() Config {
			return one(az(nsg(func(*Target) {}), nsg(func(t *Target) { t.ID = "two"; t.NSG = "one"; t.Destination = "10.9.9.9/32" })))
		}},
		{"dup resource across actions", func() Config {
			return base(map[string]ActionConfig{"a": az(nsg(func(*Target) {})), "b": az(nsg(func(t *Target) { t.ID = "two"; t.NSG = "one" }))})
		}},
	}
}

// These messages are user-facing, so a change must be deliberate.
var validationErrors = map[string]string{
	"action name":                 "invalid action name \"-bad\"",
	"az command":                  "act: Azure actions need targets and an online event",
	"az no targets":               "act: Azure actions need targets and an online event",
	"az offline event":            "act: Azure actions need targets and an online event",
	"bad check":                   "act: check type must be tcp or http",
	"check timeout":               "act: check \"x\": timeout_seconds must be 1..30 (got 31)",
	"notification cooldown":       "notifications.cooldown_seconds must be 30..86400 (got 29)",
	"bad event":                   "act: invalid or duplicate event \"reconcile\"",
	"bootstrap missing":           "act/one bootstrap_ip: not a public IPv4 address: \"\"",
	"bootstrap private":           "act/one bootstrap_ip: not a public IPv4 address: \"10.1.1.1\"",
	"command with targets":        "act: command actions need an argv array only",
	"devices with shared":         "act: devices and shared_ip_history are mutually exclusive",
	"devices prefix":              "act: devices.tag_prefix must look like netshift.test.NAME. (got \"other.device.\")",
	"devices history":             "act: devices.history_limit must be 5..10 (got 4)",
	"devices reconcile":           "act: devices.reconcile_seconds must be 60..86400 (got 59)",
	"dup event":                   "act: invalid or duplicate event \"ip_changed\"",
	"dup resource across actions": "duplicate managed Azure rule: two",
	"dup resource":                "duplicate managed Azure rule: two",
	"dup target id":               "act: invalid or duplicate target ID \"one\"",
	"empty command":               "act: command actions need an argv array only",
	"http source":                 "IP sources must be distinct HTTPS hosts without embedded credentials",
	"identity":                    "identity must be canonical user@host (lowercase host, no .local suffix)",
	"interval":                    "monitor.interval_seconds must be 5..86400 (got 4)",
	"kind":                        "one: unsupported Azure target kind \"vm\"",
	"known ip":                    "known_ips: not a public IPv4 address: \"10.0.0.1\"",
	"long interval":               "monitor.interval_seconds must be 5..86400 (got 86401)",
	"discovery timeout":           "monitor.timeout_seconds must be 1..60 (got 61)",
	"confirmations":               "monitor.confirmations must be 1..10 (got 11)",
	"offline confirmations":       "monitor.offline_confirmations must be 1..10 (got -1)",
	"retry":                       "monitor.retry_seconds must be 5..86400 (got 4)",
	"mapped bootstrap":            "mapped: mapped targets use the captured rule_shape instead of dedicated-rule fields",
	"mapped known private":        "mapped known_ips: not a public IPv4 address: \"10.0.0.1\"",
	"mapped no known":             "mapped: mapped NSG target needs nsg, known_ips, and rule_shape",
	"mapped ports":                "mapped: mapped targets use the captured rule_shape instead of dedicated-rule fields",
	"mapped shape":                "mapped: invalid rule_shape",
	"no actions":                  "configure at least one named action",
	"notifications":               "notifications.after_failures must be 1..100 (got 101)",
	"nsg destination":             "one: destination must be the intended host's IPv4 /32",
	"nsg dup port":                "one: invalid or duplicate destination port \"22\"",
	"nsg known":                   "one: unknown NSG source mode",
	"nsg mode":                    "one: unknown NSG source mode",
	"nsg no ports":                "one: invalid NSG target",
	"nsg port":                    "one: invalid or duplicate destination port \"0\"",
	"nsg priority":                "one: invalid NSG target",
	"nsg server":                  "one: invalid NSG target",
	"one source":                  "configure 2 to 4 independent HTTPS IPv4 sources",
	"pg no server":                "db: invalid PostgreSQL target",
	"pg nsg":                      "db: invalid PostgreSQL target",
	"profile":                     "profile name must be 1 to 64 lowercase letters, digits, '-', or '_', starting with a letter or digit",
	"relative az":                 "act: azure_cli must be an absolute path or a PATH command",
	"relative command":            "act: command executable must be an absolute path or a PATH command",
	"resource group":              "act/one: explicit subscription UUID, resource group, and rule required",
	"resume":                      "monitor.resume_after_seconds must be 0 or 60..86400 (got 59)",
	"retry bounds":                "monitor.max_retry_seconds must be retry_seconds (60)..86400 (got 30)",
	"rule dash":                   "act/one: explicit subscription UUID, resource group, and rule required",
	"rule":                        "act/one: explicit subscription UUID, resource group, and rule required",
	"same host":                   "IP sources must be distinct HTTPS hosts without embedded credentials",
	"shared limit":                "act: shared_ip_history needs a netshift.* tag and a limit of 5..10",
	"shared no nsg":               "act: shared_ip_history needs an NSG target to hold the registry",
	"shared tag":                  "act: shared_ip_history needs a netshift.* tag and a limit of 5..10",
	"subscription":                "act/one: explicit subscription UUID, resource group, and rule required",
	"target id":                   "act: invalid or duplicate target ID \"-x\"",
	"timeout":                     "act: timeout_seconds must be 1..1800 (got 1801)",
	"type":                        "act: unknown action type \"shell\"",
	"valid command":               "",
	"valid mapped":                "",
	"valid nsg":                   "",
	"valid postgres":              "",
	"version":                     "profile version must be 1",
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestValidationErrorsAreStable(t *testing.T) {
	cases := validationCases()
	if len(cases) != len(validationErrors) {
		t.Fatalf("%d cases, %d expected messages", len(cases), len(validationErrors))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, ok := validationErrors[c.name]
			if !ok {
				t.Fatal("no expected message")
			}
			cfg := c.build()
			if got := errorText(cfg.Validate()); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
			if want == "" {
				// Validation is idempotent: defaults filled once validate again.
				if err := cfg.Validate(); err != nil {
					t.Fatalf("revalidation: %v", err)
				}
			}
		})
	}
}

// Actions are validated in name order, so the same profile always reports
// the same error.
func TestValidationErrorIsDeterministic(t *testing.T) {
	for range 20 {
		c := Config{Version: 1, Profile: "test", Actions: map[string]ActionConfig{}}
		for _, name := range []string{"e", "d", "c", "b", "a"} {
			c.Actions[name] = ActionConfig{Type: "unknown-" + name}
		}
		if got := errorText(c.Validate()); got != `a: unknown action type "unknown-a"` {
			t.Fatal(got)
		}
	}
}

// Generated profiles (init azure, map --write-config) list the top-level keys
// in reading order.
func TestGeneratedProfileKeyOrder(t *testing.T) {
	c := Config{Version: 1, Profile: "p", Identity: "sam@laptop", KnownIPs: []string{"8.8.8.8"},
		Notifications: &NotificationConfig{Enabled: true}, Actions: map[string]ActionConfig{}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{`"version"`, `"profile"`, `"identity"`, `"known_ips"`, `"monitor"`, `"notifications"`, `"actions"`}
	last := -1
	for _, key := range keys {
		i := strings.Index(string(b), key)
		if i <= last {
			t.Fatalf("%s out of order in %s", key, b)
		}
		last = i
	}
}

func TestProfileSizeIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	base := portable(`{"version":1,"profile":"big","actions":{"hook":{"type":"command","command":["/usr/bin/true"]}}}`)
	padded := base + strings.Repeat(" ", maxConfigBytes-len(base))
	if err := os.WriteFile(path, []byte(padded), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("profile at the limit: %v", err)
	}
	if err := os.WriteFile(path, []byte(padded+" "), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, fsx.ErrTooLarge) || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized profile: %v", err)
	}
}

// encoding/json/v2 rejects invalid UTF-8, which encoding/json (v1) silently
// replaces with U+FFFD; a profile must run exactly as written, so this is an
// error.
func TestProfileRejectsInvalidUTF8(t *testing.T) {
	for name, text := range map[string]string{
		"argument": "{\"version\":1,\"profile\":\"safe\",\"actions\":{\"hook\":{\"type\":\"command\",\"command\":[\"/usr/bin/true\",\"caf\xe9\"]}}}",
		"key":      "{\"version\":1,\"profile\":\"safe\",\"actions\":{\"ho\xffok\":{\"type\":\"command\",\"command\":[\"/usr/bin/true\"]}}}",
	} {
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, []byte(portable(text)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfigRejectsTyposDuplicatesAndBroadTargets(t *testing.T) {
	t1 := fixtureTarget("one", "nsg")
	c := Config{Version: 1, Profile: "test", Actions: map[string]ActionConfig{"allow": {Type: "azure_allowlist", Targets: []Target{t1, t1}}}}
	if c.Validate() == nil {
		t.Fatal("duplicate accepted")
	}
	c.Actions["allow"] = ActionConfig{Type: "azure_allowlist", Targets: []Target{t1}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	b = []byte(strings.Replace(string(b), `"version":1`, `"version":1,"typo":true`, 1))
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, b, 0600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	t1.Destination = "0.0.0.0/0"
	c.Actions["allow"] = ActionConfig{Type: "azure_allowlist", Targets: []Target{t1}}
	if c.Validate() == nil {
		t.Fatal("broad target accepted")
	}
}

// The reviewed profile text must be exactly what runs: no duplicate or
// case-variant keys, non-canonical addresses, or case-colliding profile names.
func TestConfigRejectsAmbiguousProfiles(t *testing.T) {
	base := portable(`{"version":1,"profile":"safe","actions":{"hook":{"type":"command","command":["/usr/bin/true"]}}}`)
	for name, text := range map[string]string{
		"duplicate key":        strings.Replace(base, `"profile":"safe"`, `"profile":"safe","profile":"other"`, 1),
		"case-variant key":     strings.Replace(base, `"profile":"safe"`, `"profile":"safe","PROFILE":"other"`, 1),
		"duplicate action":     strings.Replace(base, `}}}`, `},"hook":{"type":"command","command":["/bin/rm"]}}}`, 1),
		"uppercase profile":    strings.Replace(base, `"safe"`, `"Safe"`, 1),
		"non-canonical ip":     strings.Replace(base, `"profile":"safe"`, `"profile":"safe","known_ips":[" 8.8.8.8"]`, 1),
		"trailing JSON object": base + `{}`,
	} {
		p := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	nsg := fixtureTarget("one", "nsg")
	nsg.Ports = []string{"22", "022"}
	c := Config{Version: 1, Profile: "test", Actions: map[string]ActionConfig{"allow": {Type: "azure_allowlist", Targets: []Target{nsg}}}}
	if c.Validate() == nil {
		t.Error("non-canonical duplicate port accepted")
	}
}

// trueProgram is an absolute program path on the platform running the tests,
// for profiles that are only validated.
func trueProgram() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\hostname.exe`
	}
	return "/usr/bin/true"
}

// portable replaces "/usr/bin/true" in a JSON profile with trueProgram.
func portable(profile string) string {
	quoted, _ := json.Marshal(trueProgram())
	return strings.ReplaceAll(profile, `"/usr/bin/true"`, string(quoted))
}
