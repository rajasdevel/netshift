//go:build windows

package config

import (
	"os"
	"strings"
	"syscall"
)

// accountName returns the user part of an identity for the DOMAIN\user name
// the os/user package reports on Windows (see accountNameOn).
func accountName(username string) string {
	computer, err := syscall.ComputerName()
	if err != nil {
		computer = os.Getenv("COMPUTERNAME")
	}
	return accountNameOn(username, computer)
}

// accountNameOn returns the user part of an identity for username on the
// computer named computer. A local account, whose domain is the computer
// name, is user; a domain account is domain.user, so CORP\sam and the local
// HOST\sam on one machine never share an identity. Windows account names
// ignore case, so the result is lowercase and one account always has one
// identity. A name that does not fit an identity is refused by
// CanonicalIdentity; set "identity" in the profile then.
func accountNameOn(username, computer string) string {
	domain, user := "", username
	if i := strings.LastIndex(username, `\`); i >= 0 {
		domain, user = username[:i], username[i+1:]
	}
	if domain == "" || strings.EqualFold(domain, computer) {
		return strings.ToLower(user)
	}
	return strings.ToLower(domain + "." + user)
}
