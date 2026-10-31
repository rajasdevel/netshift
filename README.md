<div align="center">

# NetShift

**Run your own scripts when your network changes.**

A tiny, dependency-free watcher for macOS and Linux that notices when your
public IP or connectivity changes and runs the actions you choose.

[![Check](https://github.com/rajasdevel/netshift/actions/workflows/ci.yml/badge.svg)](https://github.com/rajasdevel/netshift/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rajasdevel/netshift/actions/workflows/codeql.yml/badge.svg)](https://github.com/rajasdevel/netshift/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rajasdevel/netshift/badge)](https://scorecard.dev/viewer/?uri=github.com/rajasdevel/netshift)
[![Go Report Card](https://goreportcard.com/badge/github.com/rajasdevel/netshift)](https://goreportcard.com/report/github.com/rajasdevel/netshift)
[![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

Your laptop moves from home Wi-Fi to a café. Your ISP hands the router a new
address overnight. Suddenly a DNS record is stale, a firewall allowlist locks
you out, or an SSH tunnel is quietly dead. NetShift notices, double-checks, and
runs the fix for you.

```text
public IPv4 / connectivity ──► confirmed event ──► your named actions
                                                    ├─ a script or any CLI
                                                    ├─ a webhook, DNS update, tunnel restart …
                                                    └─ built-in Azure allowlisting
```

## Why NetShift

- **No false alarms.** A new IP must be reported by two independent HTTPS
  sources and, in watch mode, seen on two consecutive polls.
- **Safe by default.** Actions, cloud writes, and service removal only preview
  until you add `--apply`. `service install` leaves the service stopped until
  you add `--start`.
- **Quiet when nothing changes.** An unchanged poll is one small HTTPS request
  every 30 seconds by default: no disk writes, no subprocesses. Measured at
  well under 0.1% of one CPU core and 13–17 MiB of memory, within 1–2 MiB of a
  bare-bones Go HTTPS client ([details](docs/resources.md)).
- **Crash-safe.** NetShift records what it is about to change before changing
  it, retries failures with backoff, and never re-runs a command that already
  succeeded just because its follow-up check failed.
- **Native.** Runs as a macOS LaunchAgent or a Linux systemd user service. No
  root, no daemon framework.
- **One binary, no dependencies.** Pure Go standard library. Integrations use
  the CLIs and credentials you already have.

## Install

**Prebuilt binary.** Download the archive for your platform from
[Releases](https://github.com/rajasdevel/netshift/releases), check it against
`SHA256SUMS` (and, optionally, its build provenance with
`gh attestation verify ARCHIVE --repo rajasdevel/netshift`), then move the
extracted `netshift` onto your `PATH`. Release binaries are not signed or
notarized; see [release verification](docs/releasing.md), or build from source.
If macOS blocks a binary downloaded with a browser, run
`xattr -d com.apple.quarantine netshift`.

**With Go** (1.27 or later):

```sh
go install github.com/rajasdevel/netshift@latest
```

**From source:**

```sh
git clone https://github.com/rajasdevel/netshift.git
cd netshift
make build          # produces ./bin/netshift
```

## Quick start

The example profile has one action that runs `printenv` on the event
variables. `test-event` shows exactly what a hook would receive without running
it. The commands below use a source build; with an installed binary, use
`netshift` in place of `./bin/netshift`.

```sh
./bin/netshift --config config/example.json validate        # offline check
./bin/netshift --config config/example.json test-event ip_changed --ip 8.8.8.8
./bin/netshift --config config/example.json once            # preview only
./bin/netshift --config config/example.json once --apply    # really run it
```

`validate` and `test-event` work offline; `--ip` takes any public IPv4 as a
stand-in. `once` asks two public IP-discovery endpoints for your current
address. Without `--apply` it shows what would happen but runs no hooks,
changes no cloud resources, and saves no state. With `--apply` it runs the hook and saves state in your
[user state directory](docs/operations.md#native-paths); the JSON event lines it
prints (`action_started`, `action_completed`) show what ran. A hook's own output
is not displayed; when a hook fails, the start of its standard error is logged.
The first confirmed address counts as an `ip_changed` event.

## Write your own action

A profile is a JSON file with a monitor section (optional; sensible defaults)
and one or more named actions. Copy the example to a private file such as
`home.local.json` (the `.local.json` suffix is ignored by git) and point the
command at your own script:

```json
{
  "version": 1,
  "profile": "home",
  "actions": {
    "update_dns": {
      "type": "command",
      "on": ["ip_changed"],
      "timeout_seconds": 30,
      "command": ["/bin/sh", "/usr/local/bin/update-dns.sh"]
    }
  }
}
```

`on` defaults to `ip_changed` and `connectivity_restored`, and
`timeout_seconds` to 300 (1–1800).

Your command receives the event in its environment:

| Variable | Value |
| --- | --- |
| `NETSHIFT_EVENT` | Event name, such as `ip_changed` |
| `NETSHIFT_IP` | Current public IPv4 (last known address during an outage) |
| `NETSHIFT_PREVIOUS_IP` | Previous address, when there is one |
| `NETSHIFT_EVENT_JSON` | The whole event as JSON |
| `NETSHIFT_SOURCE`, `NETSHIFT_VALUE`, `NETSHIFT_PREVIOUS_VALUE` | Details for local events, such as interface changes |
| `NETSHIFT_TEST` | `true` when the event came from `test-event` |

Actions can subscribe to these events:

| Event | When it fires |
| --- | --- |
| `ip_changed` | A new public IPv4 passed confirmation |
| `connectivity_lost` | IP discovery failed for the configured number of polls |
| `connectivity_restored` | Discovery responded again after an outage |
| `interface_changed` | Active interface addresses changed (opt-in) |
| `monitor_resumed` | The poll timer resumed after a long gap, such as sleep (opt-in) |

A few rules keep hooks predictable:

- Commands are literal argument arrays. There is no implicit shell; call
  `/bin/sh script.sh` when you want pipes or variables.
- Hooks run as your user with a timeout. Exit code `0` is success. Any other
  exit code, a timeout, or more than 1 MiB of standard output (or 64 KiB of
  standard error) counts as a failure and retries with bounded exponential
  backoff.
- When a hook exits, anything it left running in its process group is
  stopped. Start long-running work through your service manager instead; a
  process that leaves the group and keeps the hook's output open makes the
  hook fail after 3 seconds.
- Hooks start in your home directory, whether NetShift runs from your shell or
  as a service. Use absolute paths in `command`.
- Delivery is at least once and events coalesce to the latest network state,
  so make hooks idempotent.
- A profile can run any command as you. Only run profiles you wrote or
  reviewed.

Run one action by hand with a freshly confirmed IP (it receives
`NETSHIFT_EVENT=manual`):

```sh
./bin/netshift --config home.local.json run update_dns --apply
```

See [recipes](recipes/README.md) for ready-made Route 53, webhook, and
tunnel-restart actions.

## Tune polling

Every `monitor` setting is optional. To check every two minutes instead of
every 30 seconds:

```json
"monitor": { "interval_seconds": 120 }
```

| Setting | Default | Allowed | What it controls |
| --- | --- | --- | --- |
| `interval_seconds` | 30 | 5–86400 | Pause between polls |
| `confirmations` | 2 | 1–10 | Consecutive polls that must see a new IP |
| `offline_confirmations` | 2 | 1–10 | Consecutive failed polls before `connectivity_lost` |
| `timeout_seconds` | 5 | 1–60 | Limit for each IP discovery request |
| `retry_seconds` | 30 | 5–86400 | First retry after a failed action; doubles each time |
| `max_retry_seconds` | 900 | `retry_seconds`–86400 | Longest retry delay |
| `ip_sources` | ipify and Amazon | 2–4 HTTPS URLs on different hosts | Where the public IP comes from |
| `interface_changes` | `false` | `true` or `false` | Emit `interface_changed` |
| `resume_after_seconds` | 0 (off) | 0 or 60–86400 | Emit `monitor_resumed` when a poll runs this late |

In watch mode a new address is acted on after about `interval_seconds ×
confirmations`, one minute by default; `once` and `run` confirm right away.
Each poll is one small HTTPS request, so a shorter interval costs requests,
not noticeable CPU. A running service picks up a change after
`service install --start`. The Azure action has its own reconciliation
interval, `devices.reconcile_seconds` (see the [Azure guide](docs/azure.md)).

## Run in the background

```sh
netshift --config home.local.json service install --start   # install and start
netshift --config home.local.json service status
netshift --config home.local.json service stop
netshift --config home.local.json service start
netshift --config home.local.json service uninstall --apply # keeps the profile, state, and history
```

The installer copies the binary and profile into your user directories, so
repeat `service install --start` after editing the profile or upgrading.
Without `--start`, the service is installed stopped and disabled. Each service
remembers the profile file it came from. Installing or uninstalling from a
different file with the same `profile` name is refused unless you add
`--replace`.

Services run while you are logged in. To keep one running after logout on
Linux, run `loginctl enable-linger` yourself; NetShift does not.
Paths for each platform are in the [operations guide](docs/operations.md#native-paths).

## Inspect and troubleshoot

```sh
netshift --config home.local.json doctor          # fresh diagnosis, runs no actions
netshift --config home.local.json status          # saved state, retries, last results
netshift --config home.local.json logs --follow   # this profile's event log
netshift help test-event                          # any command's options
```

Optional TCP/HTTP checks can verify that an action worked, and optional desktop
notifications report repeated failures and recovery without routine-success
noise. The [diagnostics guide](docs/diagnostics.md) covers both.

## Built-in Azure allowlisting

The `azure_allowlist` action keeps selected Network Security Group rules and
PostgreSQL flexible-server firewall rules pointed at your current IP, using your
existing `az` login. Each `user@host` device owns its own address and history,
so a roaming laptop and a home desktop keep access at the same time. NetShift
only edits the rules you select, preserves unrelated sources and comments, and
never removes a device without an explicit `devices retire`.

Get started with the read-only `init azure` command in the
[Azure guide](docs/azure.md).

## Documentation

| Guide | What's inside |
| --- | --- |
| [Operations](docs/operations.md) | File locations, permissions, operating limits, recovery |
| [Diagnostics](docs/diagnostics.md) | `doctor`, `status`, `test-event`, checks, notifications, local events |
| [Azure](docs/azure.md) | Setup, multiple machines, retirement |
| [Recipes](recipes/README.md) | DNS, webhook, and tunnel-restart examples |
| [Resource use](docs/resources.md) | What an idle watcher costs, and how to measure it |
| [Validation](docs/validation.md) | What has been tested, and how |
| [Releasing](docs/releasing.md) | Verifying downloads, reproducible builds, and the release process |

## Project status

NetShift is young and pre-1.0, so behavior may change between minor versions.
It supports macOS and Linux with IPv4; Windows and IPv6 are not implemented
yet. Read the [operating limits](docs/operations.md#operating-limits) before
enabling unattended actions, especially cloud changes.

## Contributing

Bug reports, recipes, and focused pull requests are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). `make check` runs the full offline suite,
`make lint` runs staticcheck, and no cloud credentials are needed.

Please report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
