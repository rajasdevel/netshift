package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CheckConfig is an optional TCP or HTTP probe that verifies an action worked.
type CheckConfig struct {
	Name           string `json:"name"`                      // unique within the action
	Type           string `json:"type"`                      // CheckTCP or checkHTTP
	Address        string `json:"address,omitempty"`         // host:port (CheckTCP)
	URL            string `json:"url,omitempty"`             // http(s) URL (checkHTTP)
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"` // 1..30, default 3
	ExpectedStatus int    `json:"expected_status,omitempty"` // checkHTTP status, default 200
}

// Check types.
const (
	CheckTCP  = "tcp"  // a TCP connection succeeds
	checkHTTP = "http" // a GET returns the expected status, without redirects
)

// ValidateChecks fills check defaults in place and rejects invalid checks.
func ValidateChecks(checks []CheckConfig) error {
	if len(checks) > 8 {
		return errors.New("at most 8 post-action checks are supported")
	}
	seen := map[string]bool{}
	for i := range checks {
		c := &checks[i]
		if !identifier.MatchString(c.Name) || seen[c.Name] {
			return errors.New("check names must be valid and unique within an action")
		}
		seen[c.Name] = true
		if c.TimeoutSeconds == 0 {
			c.TimeoutSeconds = 3
		}
		if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 {
			return fmt.Errorf("check %q: timeout_seconds must be 1..30 (got %d)", c.Name, c.TimeoutSeconds)
		}
		switch c.Type {
		case CheckTCP:
			host, port, err := net.SplitHostPort(c.Address)
			n, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || host == "" || strings.ContainsAny(host, "\r\n\t /") || n < 1 || n > 65535 || c.URL != "" || c.ExpectedStatus != 0 {
				return errors.New("TCP check needs a host:port address only")
			}
		case checkHTTP:
			u, err := url.Parse(c.URL)
			if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" || c.Address != "" {
				return errors.New("HTTP check needs an http(s) URL without embedded credentials or fragment")
			}
			if c.ExpectedStatus == 0 {
				c.ExpectedStatus = 200
			}
			if c.ExpectedStatus < 200 || c.ExpectedStatus > 599 {
				return errors.New("expected_status must be 200..599")
			}
		default:
			return errors.New("check type must be tcp or http")
		}
	}
	return nil
}
