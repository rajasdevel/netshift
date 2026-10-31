# Changelog

All notable changes to NetShift are documented here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, a minor version may
change behavior.

## Unreleased

### Install

- `brew install rajasdevel/tap/netshift` installs the prebuilt release on macOS
  and Linux without a Gatekeeper prompt, and `brew upgrade netshift` updates
  it. The example profiles and recipes are in `$(brew --prefix)/share/netshift`.

### Command line

- `NETSHIFT_CONFIG` names the profile when `--config` is not given, so it need
  not be repeated on every command. An explicit `--config` wins, and an
  explicit empty one, such as `--config "$UNSET"`, is refused with exit status
  2 rather than replaced by the variable. The variable must hold an absolute
  path; a relative one is also refused with exit status 2. While a command
  runs, NetShift sets it to the profile in use, so hooks see the profile that
  triggered them. `validate`, and `doctor`'s table but not its JSON, name the
  profile file they checked; `service install` still records and prints the
  absolute source path, so the `--replace` guard works as before.
- `init command --profile NAME --output FILE` writes a starter profile with
  the one command action of `config/example.json`, for installs that lack the
  example files, such as `go install`. The name is required, because state,
  history, and the service are named after it. Like `init azure`, it never
  overwrites an existing file, and the profile passes `validate`.
- `completion bash|zsh|fish` prints a shell completion script for commands,
  options, and fixed arguments such as service operations and event names. It
  is generated from the command table and each command's options, so it
  matches the binary that printed it.

### Windows (experimental)

Windows support is tested only on GitHub-hosted `windows-2025` runners and
has not yet been run on a real Windows machine.

- Releases include `windows/amd64` and `windows/arm64` builds as reproducible
  `.zip` archives holding `netshift.exe`.
- The background service is a Task Scheduler task, `\NetShift\SID\PROFILE`,
  that runs at logon as you and is started again within a minute if the
  watcher stops. NetShift changes only tasks that run as your account. `service install` (with or without `--start`, and
  `--replace`), `start`, `stop`, `status`, `uninstall`, and `doctor` work as on
  macOS and Linux, and uninstalling keeps the profile, binary, state, and
  history.
- Hooks run in a Job Object, which stops everything a hook started when it
  exits or times out, without a console window.
- `.cmd` and `.bat` programs, including the Azure CLI's `az.cmd`, run through
  `cmd.exe` with arguments NetShift quotes itself; an argument that `cmd.exe`
  would interpret (`%`, `!`, a control character, or an operator a `"` would
  leave unquoted) is refused.
- State, history, the event log, and installed profiles live under
  `%LOCALAPPDATA%\NetShift`, in files only you and SYSTEM can open. Files are
  locked with `LockFileEx`, replaced with `MoveFileEx` (write-through), and
  opened refusing symlinks, junctions, and devices; readers never block the
  watcher's writes or log rotation.
- `logs` reads and follows the event log file itself; desktop notifications
  are toasts; `init azure` prints PowerShell-quoted commands. The identity of
  a local account is `user@host`, and of a domain account
  `domain.user@host`.
- NetShift adds nothing to the macOS and Linux binaries: they are the same
  size as before.
- CI runs the Go tests and a native Task Scheduler smoke test on
  `windows-2025`, and `make lint` also analyzes the Windows build.

## 0.6.0 — 2026-10-31

First public release.

### Watching

- Confirms public IPv4 changes with two independent HTTPS sources and, in watch
  mode, two consecutive observations. Detects lost and restored connectivity.
- Optional `interface_changed` and `monitor_resumed` events reuse the poll timer
  and add no network requests. Temporary IPv6 addresses are not a change.
- Polls every 30 seconds by default, configurable from 5 seconds to a day.
  Unchanged polls make one small HTTPS request, write nothing, start no
  process, and allocate no memory in the engine. An outage is recorded once,
  even when its errors carry changing detail; a certificate error caused by a
  wrong system clock says so.
- Discovery connections are reopened at least every five minutes, counting
  time asleep, so a moved route is noticed.

### Actions

- Command hooks run literal argument arrays with `NETSHIFT_*` event variables,
  a timeout, bounded output, and their own process group, which is stopped
  when the hook exits. Hooks start in the home directory.
- Failures retry with bounded exponential backoff. Intents are saved before
  each action, and optional TCP/HTTP checks retry without repeating a command
  that already succeeded. Stopping the watcher or interrupting `run` keeps the
  work pending without counting a failure.
- Optional desktop notifications report repeated failures and recovery.
- `test-event` previews an event without side effects; `run NAME` runs one
  action with a freshly confirmed IP.

### Built-in Azure allowlisting

- Keeps selected NSG rules and PostgreSQL flexible-server firewall rules pointed
  at each registered `user@host`, using the installed Azure CLI.
- Preserves unrelated sources, comments, ports, and priorities; refuses
  unexpected rule shapes and case-variant rule names; never recreates a missing
  rule from watch. Addresses shared with other active devices, such as a NAT
  or VPN egress pool, stay allowed and never block updates.
- Explicit, durable retirement visits every target, always revokes database
  access, previews exactly what applying would do, and fails rather than
  reporting success if any address of the retired device stays allowed.
- Device records are sized so a retirement marker always fits, and one NSG tag
  slot is kept free for it. Device actions that would share records or rules
  are refused.
- Read-only `init azure` and `map` build reviewed profiles from existing rules.

### Operations

- Native macOS LaunchAgent and Linux systemd user service, installed without
  root. `--start` activates it; `--replace` deliberately takes over (or
  uninstalls) a service installed from another profile file. Uninstall keeps
  the profile, state, and history.
- `doctor`, `status`, `logs`, `history`, and `help COMMAND`. Options may come
  before or after arguments; invalid command lines exit with status 2.
- Service commands and `doctor` treat an unresponsive `launchctl` or
  `systemctl` as an error, not as a stopped service. On Linux, service files
  follow the systemd user manager's configuration directory.

### Safety

- Actions, cloud writes, and service removal preview until `--apply`.
- Profiles are parsed strictly: duplicate, case-variant, and unknown keys and
  invalid UTF-8 are errors, and addresses and ports must be canonical. An
  out-of-range setting is reported with its name, allowed range, and value.
- State, history, log, and lock files refuse symlinks and have size limits.
  Writes are synced, a failed history append is rolled back, and `--log-file`
  may not name the profile or its state files.
- Release archives are reproducible and ship with checksums and build
  provenance. CI runs the race detector, `go vet`, staticcheck, and
  govulncheck on macOS and Linux, plus CodeQL; parsers of untrusted input
  are fuzz-tested.
