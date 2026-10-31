// Command netshift runs your actions when a macOS or Linux machine's public
// IPv4 address or connectivity changes.
//
// Usage:
//
//	netshift --config FILE validate
//	netshift --config FILE test-event ip_changed --ip 8.8.8.8
//	netshift --config FILE service install --start
//
// Actions are command hooks or the built-in Azure allowlist. Actions and cloud
// writes only preview until --apply. Run "netshift help" for every command;
// documentation is at https://github.com/rajasdevel/netshift.
package main

import "github.com/rajasdevel/netshift/internal/cli"

func main() { cli.Main() }
