# Diagnostics, checks, and local events

## Diagnose and inspect

```sh
netshift --config work.local.json doctor
netshift --config work.local.json doctor --checks
netshift --config work.local.json doctor --azure --json
netshift --config work.local.json status
netshift --config work.local.json status --json
netshift --config work.local.json logs --follow
netshift --config work.local.json logs --lines 100 --json
```

`doctor` validates the loaded profile and state, confirms the public IPv4
through the discovery sources, checks that each action's executable exists, and
inspects the native service.
`--checks` probes configured targets. `--azure` requests a CLI access token for
each selected subscription; it never prints tokens or tests write permissions.
No action is executed and no cloud rule is changed. A failure exits nonzero;
optional features that are not set up, such as an uninstalled service, produce
warnings. Credentials and Azure CLI
cache refresh remain the CLI's responsibility. Tools invoked inside your scripts
must be checked separately.

A service installed without `--start` is a warning ("installed, not started").
An enabled service that is not running fails, as does a service manager that
does not answer; on macOS, read `~/Library/Logs/NetShift/PROFILE.stderr.log`.
Without a reachable systemd user manager, the Linux service check is a warning.
Command actions fail while an argument still holds a recipe placeholder
(`/absolute/path/to/`, or a `YOUR_…` word) or names a script that does not
exist. `doctor` finds the script run by common shells, Python, Perl, Ruby,
Node.js, and `osascript`; for an option it does not recognize, it skips the
check rather than guess. Relative script paths, which resolve against your home
directory, are a warning. Multi-line details are joined with
"; " in the table; `--json` keeps them verbatim.

`status` is readable by default; `--json` prints the saved state as JSON.
Saved observations are not proof that the watcher is currently running. `doctor`
performs a fresh service check. Status distinguishes a pending action from
pending verification after the action has already completed.

`logs` reads only the selected profile: its rotated event file on macOS, or its
systemd journal on Linux, filtered by both the current UID and user-unit name.
This works with unified or split journals; access remains subject to OS journal
permissions. Before the service has written anything, `logs` reports that no
event log exists yet and exits 1. Use `--file FILE` for the event log of a
watcher run in the foreground or with `--log-file`. Following uses a subprocess only while that CLI command is open, exits on
Ctrl-C, and keeps bounded line buffers. No permanent log reader is added.

## Test an event

```sh
netshift --config config/example.json test-event ip_changed \
  --ip 8.8.8.8 --previous-ip 1.1.1.1
netshift --config config/example.json test-event connectivity_lost --action my_network_hook
```

The default prints selected actions, literal argv, checks, and event environment
without discovery requests, action calls, Azure reads or writes, or state changes.
The IPs above are well-known public resolvers used as stand-ins, not addresses to
allowlist. Event IPs must be public, so private and documentation ranges are refused.
Use `--value` and `--previous-value` to test local-source events. `NETSHIFT_TEST`
is `true` for simulation and `false` for normal events.

`--apply` explicitly executes command hooks and their checks. This can have real
external effects; use a test destination you control. Azure actions are always
refused in applying simulations, and mixed selections fail before any command
runs. Use `--action NAME` to select a subscribed command. Simulation never writes
the working profile's state/history or generates failure notifications.

## Check the result of an action

Add optional checks to an action:

```json
"checks": [
  {"name": "database", "type": "tcp", "address": "db.example.com:5432", "timeout_seconds": 3},
  {"name": "application", "type": "http", "url": "https://app.example.com/health", "expected_status": 200}
]
```

TCP checks open and close a connection; they do not authenticate or issue a
query. HTTP checks use GET, require the expected status, do not follow redirects,
and close without consuming the response body. They test the selected endpoint,
not an application's entire correctness contract. URLs cannot embed credentials.
Checks are sequential, limited to eight per action and 1–30 seconds each, within
the action's total timeout. The default is three seconds and HTTP status 200.

Checks run only after actions or an explicit `doctor --checks`. They do not add
background network polling. After an action succeeds, NetShift saves a receipt
before probing. A failed check retries with the existing backoff; it does not
repeat the successful command. The receipt survives restart. A new event or a
changed profile supersedes the receipt. As with all command hooks, a crash between an external
effect and saving its receipt can repeat work; keep hooks idempotent.

Azure device reconciliation continues at its separately configured interval,
even while a check is failing, so remote retirement is still observed. An
explicitly retired identity skips verification and does not emit a misleading
recovery notification. Checks never authorize recreating a missing NSG rule.

## Failure and recovery notifications

```json
"notifications": {
  "enabled": true,
  "after_failures": 3,
  "cooldown_seconds": 300
}
```

Apart from `enabled` (off by default), the values shown are the defaults
(`after_failures` 1–100, `cooldown_seconds` 30–86400). This optional top-level setting sends one desktop notice after repeated action
or verification failures, then one on recovery. Healthy polls and successful
routine actions remain quiet. Alert state persists across restarts. The cooldown
bounds helper retries and new failure notices; recovery can be sent promptly.

macOS uses its existing `osascript` helper. Linux uses `notify-send` when available
in a graphical user session; NetShift does not install it. Missing helpers,
headless sessions, permission denial, or OS notification settings may prevent a
banner. Delivery is best effort, and a crash around delivery can duplicate a
notice. Notifications never fail an otherwise successful action. `doctor` checks helper
availability, not visible delivery. Notification text names the profile/action;
it does not include IP history, credentials, or raw provider errors.

## Two opt-in event sources

```json
"monitor": {
  "interface_changes": true,
  "resume_after_seconds": 300
}
```

| Event | Meaning | Cost |
| --- | --- | --- |
| `interface_changed` | The set of active non-loopback interface addresses changed, including VPN addresses | Local interface/address reads on the existing poll; no network request or helper |
| `monitor_resumed` | The watch timer ran at least the configured number of seconds late | One wall-clock comparison per existing poll |

Both are disabled by default. First interface observation establishes a baseline;
unchanged snapshots do nothing. IPv6 addresses are compared by network prefix, so
rotating temporary (privacy) addresses do not count as a change. These are observations at poll boundaries, not
an OS event stream: brief transitions between polls can be missed. A long timer
gap can reflect sleep, a suspended process, scheduling delay, or a forward clock
change. Long actions are excluded from the expected wake time. The resume
threshold is 60–86400 seconds; zero disables it.

Subscribe command actions through their `on` list. Azure's built-in action accepts
only confirmed IP/network-recovery events. Local events include the last known
public IP, which may be stale. For `interface_changed`, `NETSHIFT_SOURCE` is
`interfaces` and `NETSHIFT_VALUE`/`NETSHIFT_PREVIOUS_VALUE` are the address
sets; for `monitor_resumed`, `NETSHIFT_SOURCE` is `watch_timer` and
`NETSHIFT_VALUE` is how many seconds late the poll ran. Everything is also in
`NETSHIFT_EVENT_JSON`. Interface
values can contain private/local IPv4 and IPv6 addresses; review outgoing hooks.

To remove a background service, see [operations](operations.md#background-service).
