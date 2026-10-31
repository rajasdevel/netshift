# Azure action

NetShift uses your authenticated Azure CLI to keep selected access rules aligned
with each registered device. No Azure SDK or separate credentials are required.

## Set up Azure

Prerequisites: `az` on `PATH`, a working `az login`, and access to the resources
you select. NetShift always passes an explicit subscription UUID; it never
changes your default subscription. See [Azure permissions](operations.md#azure-permissions).

Start with existing inbound Allow rules that contain an IP you know is yours.
Replace the uppercase values below with your resources and owned public IPv4:

```sh
netshift init azure \
  --profile work \
  --subscription YOUR_SUBSCRIPTION_UUID \
  --known-ip YOUR_CURRENT_OR_PREVIOUS_PUBLIC_IPV4 \
  --nsg-rule YOUR_GROUP/YOUR_NSG/YOUR_RULE \
  --postgres-server YOUR_GROUP/YOUR_POSTGRES_SERVER \
  --output work.local.json
```

Repeat `--nsg-rule`, `--postgres-server`, and `--known-ip` as needed. PostgreSQL is
optional. At least one NSG rule is required to hold the shared device registry.
`init` reads only the selected resources, captures their permissions and
comments, and creates a private local profile. It does not write to Azure or
overwrite an existing file. Rules without a matching confirmed owned IP are
refused. The seed IPs belong only to the identity that generated the profile.

Review the selected targets, then preview and enroll:

```sh
netshift --config work.local.json identity
netshift --config work.local.json validate
netshift --config work.local.json devices enroll
netshift --config work.local.json devices enroll --apply
netshift --config work.local.json service install --start
```

`config/azure.example.json` is a valid, synthetic schema example. Use `init` for
real resources so the rule fingerprints and templates come from Azure.

## Multiple machines

Copy the portable profile and the appropriate binary to another machine.
Authenticate its Azure CLI, preview enrollment, then enroll and install its
native service using the commands above. Do not copy another machine's state,
history, or installed profile.

Identities are `user@host`, such as `sam@laptop` and `sam@desktop`. Hostnames are
lowercased and `.local` is removed. The portable profile detects the local
identity; installation pins it in that machine's service configuration.

- Each identity owns a separate JSON tag on every selected NSG, containing its
  current IP, recent history, and revision. The history limit is 5–10 addresses.
- NSG source lists retain the union of active identities' current IPs and all
  unrelated entries. Shared home IPs remain until their last active owner moves
  or retires. Historical addresses do not grant access.
- PostgreSQL gets one stable rule per identity/server. First enrollment creates
  it; subsequent IP changes update the same name. Unconfigured existing rules
  are preserved. Rule names include a readable identity and a hash.
- Comments, other tags, ports, priorities, and destinations stay unchanged.
  Unrecognized ownership or changed rule shapes stop the action for inspection.
- Two device actions may share a registry NSG only with tag prefixes that do
  not overlap, and may not share a PostgreSQL server, because per-identity rule
  names depend only on the profile.

```sh
netshift --config work.local.json devices list
netshift --config work.local.json history --limit 20
netshift --config work.local.json status
```

## Explicit retirement

There is no automatic expiry. An offline device retains access until it updates
or is retired explicitly. Stop the local writer before applying a device command:

```sh
netshift --config work.local.json service stop
netshift --config work.local.json devices retire sam@desktop
netshift --config work.local.json devices retire sam@desktop --apply
netshift --config work.local.json service start
```

When retiring the local identity, leave its service stopped. Retirement removes
only access no remaining identity needs and deletes that identity's PostgreSQL
rules. A JSON retirement marker prevents a sleeping watcher from re-enrolling.
A wholly owned NSG rule with no remaining source is deleted; mixed rules retain
unrelated sources. Retirement of a different username is refused.

Reactivation is explicit on the retired identity's host:

```sh
netshift --config work.local.json devices activate --apply
netshift --config work.local.json service start
```

Keep that identity's other processes stopped during activation. Only explicit
enrollment/activation can restore a missing NSG rule from its reviewed template;
watch never recreates one. See [recovery](operations.md#recovery).

Retirement visits every target even if one fails, so database access is always
revoked; it reports all failures together and keeps the device record until
every target is clean. A managed rule that no longer exists has nothing to
remove. Removing the retired device's addresses is logged as
`retired_address_removed`. If the device changes IP during retirement, the
retirement marker is extended to cover it. A preview without `--apply` reports
the same outcome as applying would.

A registry record this version cannot read, such as one written by a newer
client, is logged as `device_record_skipped`, and no address it mentions is
added or removed. If that leaves an address of the retired device allowed,
retirement logs `retired_address_retained`, keeps the device record, and fails;
fix or remove the unreadable record, then retry. Enrolling a retired identity
fails with `identity is retired; use devices activate`.

## Why reconciliation always re-reads Azure

Every periodic reconciliation (every 30 minutes by default; set
`devices.reconcile_seconds`, 60–86400, to change it) reads the selected rules
and device records fresh, even when this machine's IP has not changed.
A stable local IP does not prove that shared Azure state is unchanged:

| Situation | What a cached shortcut could miss |
| --- | --- |
| Another machine enrolls or changes IP | A new active address that must stay in the rule |
| A peer retires this identity | A retirement marker that must stop this writer |
| An earlier write timed out or the process stopped | A pending intent that must be reconciled before another change |
| Someone deletes or edits a managed rule | Changed permissions, ports, or ownership that must stop the action |
| Authentication, throttling, or reads fail | A failure that must be reported and retried, not hidden by old success |

Within one pass, NetShift skips only reads that pass already made: a registry
tag already at its wanted value with no pending write, and a PostgreSQL rule the
pass's listing showed at the desired address or absent. Writes always follow a
fresh read and are verified by reading back; no snapshot is kept between
reconciliation cycles. With two NSGs and one database server, an unchanged
reconciliation runs 8 Azure CLI commands.
