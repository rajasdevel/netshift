# Operating NetShift

This guide covers where NetShift keeps its files, how the background service
behaves, the limits to know before running it unattended, and recovery. For
`doctor`, checks, notifications, and event testing, see the
[diagnostics guide](diagnostics.md); for CPU and memory, see
[resource use](resources.md).

## Native paths

For a profile named `work`:

| Item | macOS | Linux |
| --- | --- | --- |
| Service | `~/Library/LaunchAgents/dev.netshift.work.plist` | `~/.config/systemd/user/netshift-work.service` |
| Binary (shared by all profiles) | `~/Library/Application Support/NetShift/bin/netshift` | `~/.config/netshift/bin/netshift` |
| Installed profile | `~/Library/Application Support/NetShift/profiles/work.json` | `~/.config/netshift/profiles/work.json` |
| State | `~/Library/Application Support/NetShift/state/work.json` | `~/.local/state/netshift/work.json` |
| History | `work.history.jsonl` beside the state file | same |
| Event log | `~/Library/Logs/NetShift/work.log` | `journalctl --user -u netshift-work.service` |
| Crash output | `~/Library/Logs/NetShift/work.stderr.log` | `journalctl --user -u netshift-work.service` |

On Linux, the service, binary, and installed profile live under the systemd
user manager's `XDG_CONFIG_HOME` (as `systemctl --user show-environment`
reports it), or `~/.config` when the manager has none. A value set only in your
shell is ignored, because systemd would not look there, so service commands
need a running user manager. The default state path honors `$XDG_STATE_HOME`.

On Windows (experimental), everything lives under `%LOCALAPPDATA%\NetShift`,
which stays on the machine. Every file NetShift creates there is private, as
mode 0600 makes it on macOS and Linux: its access list does not inherit the
folder's and grants access only to you (the file's owner) and SYSTEM, not to
administrators.

| Item | Windows |
| --- | --- |
| Service | Task Scheduler task `\NetShift\SID\work`, where SID is your account's security identifier, defined by `%LOCALAPPDATA%\NetShift\tasks\work.xml` |
| Binary (shared by all profiles) | `%LOCALAPPDATA%\NetShift\bin\netshift.exe` |
| Installed profile | `%LOCALAPPDATA%\NetShift\profiles\work.json` |
| State | `%LOCALAPPDATA%\NetShift\state\work.json` |
| History | `work.history.jsonl` beside the state file |
| Event log | `%LOCALAPPDATA%\NetShift\logs\work.log` |
| Crash output | Not captured; the event log keeps the error that stops the watcher |

## Background service

`service install` copies the binary and profile into the paths above, resolves
each action's executable on this machine, and pins the device identity. It
also records `PATH`, `AZURE_CONFIG_DIR`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`,
`SSL_CERT_DIR`, and `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` (either case) in the
service definition. Proxy URLs, including any credentials in them, are written
into that private file.

On Windows a task cannot carry environment variables: it runs with your
account's saved environment (Settings, or System Properties > Environment
Variables), not your shell's. Set `HTTPS_PROXY`, `AZURE_CONFIG_DIR`, and the
like there for the service to see them.

Editing your profile does not change the installed copy: repeat
`service install --start` to deploy profile or binary changes. All profiles of
one user share the installed binary, so an upgrade applies to each profile the
next time it starts.

- Without `--start`, the service is installed stopped and disabled.
- Each definition records its source profile in a `NetShift source:` comment.
  Installing a different profile file with the same `profile` name is refused
  unless you add `--replace`. Definitions NetShift did not write are never
  replaced.
- On macOS, `service install --start` restarts an unchanged job in place. For a
  changed definition it waits up to 10 seconds for the old job to unload before
  loading the new one; `service stop` waits the same way.
- Both service managers start the watcher, and therefore its hooks, in your
  home directory.
- On macOS, standard error goes to `work.stderr.log`: Go panics, and the error
  that stops the watcher. launchd relaunches a failing watcher every 10
  seconds, adding that error each time; NetShift empties the file at start
  once it exceeds 1 MiB. The systemd unit restarts a failed watcher every 10
  seconds with no start limit, so a crash loop at login never leaves it failed.
- Services run while you are logged in. To keep one running after logout on
  Linux, run `loginctl enable-linger` yourself; NetShift does not.

### Windows (experimental)

The Windows service has been verified only on GitHub-hosted `windows-2025`
runners, whose account is an administrator; see [validation](validation.md).

- The service is a Task Scheduler task, `\NetShift\SID\PROFILE`, in a folder
  of its own for your account, so another account's profile of the same name
  never shares it. It runs `watch --apply` as you, with your normal (not
  elevated) rights, only while you are logged on, so it can use your Azure CLI
  sign-in and show notifications. Creating it is meant to need no
  administrator; that has not been checked yet, because CI's account is one.
- Before NetShift changes, starts, ends, replaces, or deletes the task, it
  reads the task's account from Task Scheduler and refuses unless it is yours,
  even when you could change another account's task as an administrator.
  `service install` also refuses a registered task whose definition file is
  missing, unless you add `--replace`.
- It starts at logon. Task Scheduler's own restart setting only covers a task
  that fails to launch, so the task is also triggered every minute: a trigger
  does nothing while the watcher runs and starts it again within a minute
  after it exits. `service stop` disables the task, which stops both triggers,
  and ends the watcher.
- Without `--start`, the task is registered disabled, so no trigger runs it.
- Ending the task stops the watcher at once, without a graceful shutdown. Its
  saved state survives this as it survives a crash, and the hooks it started
  are stopped with it.
- A running watcher keeps `netshift.exe` open, and Windows cannot replace a
  running program. `service install` therefore stops this profile's task
  before writing anything. If another profile's watcher still runs the shared
  binary, the old file is renamed to `netshift.exe.ID.old`, and a later install
  removes it once nothing runs it.
- A console window may flash briefly when the task starts the watcher; the
  watcher then closes it. The task passes `--scheduled-task` for this, so a
  `watch` you start yourself keeps its window, Ctrl+C, and error output.
  Programs the watcher starts get no window.
- Your identity is `user@host` for a local account, and `domain.user@host`
  for a domain account (`CORP\sam` on `host` is `corp.sam@host`), lowercase,
  so a local and a domain account of the same name stay apart. An account
  whose name does not fit an identity needs `"identity"` set in the profile.
- Go runtime crashes are not captured, because a task has no standard error.
  The event log still records the error that stops the watcher.

To remove a service:

```sh
netshift --config work.local.json service uninstall           # preview
netshift --config work.local.json service uninstall --apply
```

The preview names the profile file the service was installed from
(`Installed from:`); a service installed from a different file with the same
`profile` name is refused unless you add `--replace`. Applying stops and
removes only this profile's service definition. The profile,
the shared binary, state, history, and other profiles stay. Cloud registrations
stay active: run `devices retire` separately when the machine should lose
access. Unmanaged or symlinked definitions, and loaded services without a
verifiable definition, are refused.

## Files and logs

State and profile files are private to your user. A file lock admits one
writer per state file, so stop the service before running a command with
`--apply` for the same profile. State, history, log, and lock files must be
regular files: NetShift refuses a symlink in their place and never writes
through one. A state file larger than 64 MiB or a profile larger than 1 MiB is
refused rather than read. `--log-file`, and its `.1` backup, must not be the
profile or its state, history, or lock file.

macOS and Windows event logs rotate at 1 MiB plus one backup; Linux uses the
journal's retention. On Windows, NetShift opens its files so that a reader,
such as `status` or `logs --follow`, never blocks the watcher from replacing
the state file or rotating the log. The history file is the append-only audit trail and does not rotate.
It records the identity, operation ID, resource ID, before and after values,
each intent, and each verification. A failed append, such as on a full disk,
is rolled back; an incomplete final record left any other way (for example by
a crash) blocks further writes until it is preserved and repaired. Back up the
profile, state, and history. Several watchers may share one `--log-file`;
rotation is coordinated with a file lock.

## Azure permissions

Use an authenticated CLI principal with access only to the selected resources.
NetShift does not create credentials, change role assignments, or grant itself
permissions. It uses:

| Scope | Required operations |
| --- | --- |
| Selected NSGs | Read the NSG and its rules; update selected rule sources; merge and delete its own namespaced tags |
| Explicit enrollment or retirement | Create or delete a selected rule when restoring or removing a last-owner rule |
| Selected PostgreSQL servers | Read the server and firewall rules; create, update, and delete per-identity firewall rules |
| Optional `map` inventory | List NSGs in the selected subscription |

Azure RBAC permissions often apply to a whole resource rather than to
individual fields. `user@host` identities and JSON tags are ownership
bookkeeping, not authentication or a boundary between mutually untrusted Azure
administrators: anyone with write access to a registry can change it. Tag
values hold plaintext IPs and device names, never credentials.

Use [Azure custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
when built-in roles are broader than you need. NetShift never needs Owner.
Check the effective permissions in your own subscription; NetShift installs no
role definition.

## Operating limits

- **IPv4 only.** Connectivity means a usable answer from the configured
  discovery endpoints, not OS link state or the health of other applications.
- **Confirmation.** A new IP needs two distinct HTTPS sources. Ranges, wildcard,
  private, and documentation-only addresses are rejected. An unchanged IP needs
  one successful source; failures or disagreement never supply a new IP.
- **Sequential actions.** Observation and actions share one loop, so a slow
  action delays the next observation. Some PostgreSQL operations take about a
  minute even for one rule. Device actions default to a 900-second deadline,
  configurable up to 1800 seconds. A second IP change during a long action is
  handled after it finishes, fails, or is stopped. Stopping the service cancels
  the action and keeps its journal for reconciliation.
- **Tag capacity.** Each selected NSG holds one JSON record per identity, and
  each record must fit one 256-byte tag value, so a long `user@host` may keep
  fewer past addresses than `history_limit` (5–10). Each record is sized so it
  still fits as its retirement marker. If an owned address still in a rule
  cannot fit, the action stops instead of forgetting it; addresses another
  active device is currently at don't count, because that device's record
  keeps them. Retirement markers persist. Azure allows 50 tags per resource;
  NetShift never lets a device record or migration marker take an NSG's last
  free slot, so a retirement marker always fits.
- **Profile names.** `devices.tag_prefix` must start with `netshift.<profile>.`.
  PostgreSQL rule names include the profile name, so machines that share a
  registry must use the same profile name. `tag_prefix` is stored lowercase.
- **Ownership is decided by address.** An IPv4 address in any registered
  device's history, including a retired device's, counts as managed in that
  rule. If such an address is later granted to someone else in the same rule,
  NetShift may remove it; use a separate rule for addresses it does not own.
  Each removal of an address that was not in the rule when this identity last
  verified it is logged as `unplaced_address_removed`; during retirement, the
  retired device's own addresses are logged as `retired_address_removed`.
- **No automatic expiry.** An offline device's old address stays allowed until
  it changes or the device is retired. Review registrations when a machine is
  lost or permanently disconnected.
- **No atomic cloud writes.** Azure CLI writes are not compare-and-swap, and no
  transaction spans NSGs and database servers. Fresh reads, guarded updates,
  read-back verification, up to three convergence passes, and periodic
  reconciliation reduce conflicts, but simultaneous writers can briefly restore
  a stale source list. Coordinate administrator edits and last-owner
  retirement or reactivation.
- **One writer per identity.** Run one profile writer per machine with unique
  host identities. Do not clone pinned identities or state.
- **Azure CLI login.** Renewing authentication is the Azure CLI's job. Login
  failures are logged and retried; run `az login` as the same user when needed.
- **Batch files on Windows.** The Azure CLI on Windows is `az.cmd`, a batch
  file, and Windows runs batch files through `cmd.exe`, which interprets some
  characters even in quoted arguments. NetShift runs `.cmd` and `.bat`
  programs (the Azure CLI or a hook) through `cmd.exe` itself, quoting every
  argument for the program behind it. It refuses an argument that contains
  `%`, `!`, a line break, or another control character, which `cmd.exe`
  expands or stops at even inside quotes, and one whose `"` characters would
  leave one of `& | < > ( ) ^` outside `cmd.exe`'s quotes, rather than risk it
  being read differently. JSON such as the device tags passes. A rule
  description that breaks these rules cannot be restored on Windows. For hooks
  that need such arguments, use an `.exe`, or run PowerShell with `-File` and
  a script.
- **Status is not proof.** Saved status and old check receipts don't prove
  present connectivity. Confirm the current IP and the live rules before
  assuming a rapid change succeeded.

## Recovery

After an interrupted operation, inspect `status`, `history`, and fresh Azure
state. Intents are saved before writes; a retry reads the result and reconciles
an ambiguous success before making another change. A history record is
evidence, not a rollback command: preserve unrelated current sources when
reversing a change, and never delete state or history to get past an ownership
guard.

Use `devices enroll` to review restoring a missing configured NSG rule. The
stored template keeps the reviewed permissions and captured description (a
description that starts with `@` is refused, because the Azure CLI would read it
as a file name);
ordinary source updates keep the current live description. The template is not
a backup of every unrelated source. Changed permissions need a fresh, reviewed
mapping. Retry a retirement with the same identity argument.

## Converting a single-IP profile to per-device

A profile whose Azure action has no `devices` block manages one shared address,
for example one produced by `map --write-config`. To convert it:

```sh
netshift --config single.local.json map --per-machine \
  --output inventory.local.json --write-config proposed.local.json
netshift --config proposed.local.json devices enroll
```

Review the proposed profile before applying it. `map --per-machine` sets
`legacy_tag` only when the single-IP profile used shared IP history or a
managed NSG still has `netshift.<profile>.ip-history`. Only `legacy_identity`
adopts the earlier unlabeled history and configuration. Its per-identity
PostgreSQL rules are verified before the configured shared rule names are
removed. The shared-history tag becomes a versioned migration marker that the
single-IP profile rejects, so stop every machine still running the single-IP
profile and move it to the converted profile before enrolling more identities.

Profiles from `init azure` instead use `seed_identity` for the explicitly
confirmed seed IPs. Other identities cannot inherit those claims. Initial setup
keeps every unconfigured PostgreSQL rule; it never infers which old rules can
be removed.

## Inventory and extension

`map` is an explicit, read-only inventory of the NSGs in one subscription. It
matches exact owned IPv4 or /32 entries, never infers ownership from names,
comments, or nearby addresses, and reads ownership records only from the NSGs
the action manages. `--write-config` writes a proposal; the watcher never adds
targets on its own.

For another provider or a local workflow, add a `command` action. See the
[README](../README.md#write-your-own-action) for the hook contract.

References: [NSG rules](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview),
[resource tags](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources),
[PostgreSQL CLI](https://learn.microsoft.com/en-us/cli/azure/postgres/flexible-server/firewall-rule),
[systemd user units](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
