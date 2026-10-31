package config

import (
	"fmt"
)

// NotificationConfig enables desktop notifications for repeated action
// failures and the recovery that follows.
type NotificationConfig struct {
	Enabled         bool `json:"enabled"`
	AfterFailures   int  `json:"after_failures,omitempty"`   // consecutive failures before alerting, 1..100, default 3
	CooldownSeconds int  `json:"cooldown_seconds,omitempty"` // minimum time between attempts, 30..86400, default 300
}

// ValidateNotifications fills defaults in place and checks their bounds. A
// nil configuration disables notifications.
func ValidateNotifications(c *NotificationConfig) error {
	if c == nil {
		return nil
	}
	if c.AfterFailures == 0 {
		c.AfterFailures = 3
	}
	if c.CooldownSeconds == 0 {
		c.CooldownSeconds = 300
	}
	if c.AfterFailures < 1 || c.AfterFailures > 100 {
		return fmt.Errorf("notifications.after_failures must be 1..100 (got %d)", c.AfterFailures)
	}
	if c.CooldownSeconds < 30 || c.CooldownSeconds > 86400 {
		return fmt.Errorf("notifications.cooldown_seconds must be 30..86400 (got %d)", c.CooldownSeconds)
	}
	return nil
}
