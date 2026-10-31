//go:build windows

package config

import "strings"

// accountName returns the user part of an identity for the account name the
// os/user package reports. Windows reports DOMAIN\user, and its account
// names ignore case, so one account always has one identity.
func accountName(username string) string {
	return strings.ToLower(username[strings.LastIndex(username, `\`)+1:])
}
