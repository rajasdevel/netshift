# NetShift

A small macOS/Linux network-event utility. Keep the runtime dependency set to
this binary and commands the user already has, such as the Azure CLI. Also
follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Build and test

- Use current stable Go and the standard library only. Do not add Azure SDKs,
  containers, a database, or Go module dependencies.
- Run `make check` and `make lint` before proposing a change. Build with
  `go build -o /dev/null .`; a plain `go build` writes `./netshift`.
- Never use live cloud mutations as a test without explicit user authorization.
  Tests use fakes that follow Azure semantics (case-insensitive names, `create`
  is an upsert).
- List every new public file in `release-files.txt`.
- `main.go` only calls `cli.Main`; code lives in `internal/` packages, and
  imports point down the layering in CONTRIBUTING.md's code layout. The Azure
  action is `internal/engine/azure_*.go`.
- `make fuzz` exercises the parsers of untrusted input (profiles, IPs, Azure
  tags); add a seed when you fix a parsing bug.

## Safety invariants

- Cloud writes require explicit `--apply`. Service activation requires `--start`.
- Own only the configured NSG rules and the deterministic per-identity
  PostgreSQL rules. Preserve other sources, ports, priorities, permissions, and
  unrelated local files. Refuse unexpected rule shapes.
- Persist intent before an external write, and verify the result afterward.
- Device identity is canonical `user@host`; keep each identity's metadata and
  local history separate. Never adopt another user's bootstrap/history records.
- Retirement requires an explicit command and durable tombstones. Never expire
  offline identities or remove a tombstone from watch.
- Create a PostgreSQL identity rule only after a successful list proves it
  absent; reuse its stable name for IP updates. Verify a replacement before
  removing an explicitly owned legacy rule.
- Preserve the union of active device IPs, including shared NAT addresses.
  Azure CLI writes are not compare-and-swap; re-read, verify, and retry
  boundedly. Route every engine Azure CLI call through `Engine.az`.
- Watch must not recreate a missing NSG rule. Only explicit enrollment may
  restore the reviewed template after last-owner retirement.
- Post-action verification must persist the action receipt and retry checks
  without repeating completed command hooks. Preserve scheduled device
  reconciliation.
- Test-event preview has no side effects; applying simulations must refuse Azure.
- Service uninstall is profile-scoped and preserves history and cloud ownership.
- Parse profiles with `encoding/json/v2` so duplicate, case-variant, and unknown
  keys fail. Hooks run in their own process group, stopped when they exit.

## Quiet, bounded polling

- Keep unchanged monitoring quiet. Bound every network request and subprocess.
- Optional sources and helpers must do no work when disabled. Quiet cycles must
  not write state, spawn helpers, or run target checks.
- The idle checkpoint shortcut must never bypass explicit action saves or treat
  a failed save as a no-op. Keep event-only state durable without subscribers.
- Use current Go timer Reset semantics; keep the full poll delay after work.
  Use `testing/synctest` for deterministic timer tests. Do not slow polling.
- Use launchd on macOS and systemd user services on Linux. Windows is not
  supported.
