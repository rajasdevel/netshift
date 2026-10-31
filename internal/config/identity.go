package config

import (
	"encoding/json"
	"fmt"
)

// JSON returns c as indented JSON with a final newline.
func JSON(c Config) ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// IdentityOf resolves a profile's user@host identity; tests replace it.
var IdentityOf = ResolveIdentity

// WithIdentity resolves the profile's user@host identity. Only commands that
// bind state or cloud ownership to the identity call it, so an unusual host
// name never blocks status, logs, or service stop/uninstall.
func WithIdentity(c Config) (Config, error) {
	if !HasDevices(c) {
		return c, nil
	}
	id, err := IdentityOf(c.Identity)
	if err != nil {
		return c, fmt.Errorf("identity: %w", err)
	}
	c.Identity = id
	return c, nil
}
