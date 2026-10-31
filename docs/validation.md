# Validation record

Results for `0.6.0`, last updated 2026-10-31.

| Evidence | Result | Scope |
| --- | --- | --- |
| Go tests, race detector, vet, staticcheck, govulncheck | PASS | All Go tests; macOS ARM64, Go 1.27.3 |
| Fuzzing | PASS | Profile parsing, IP canonicalization, and Azure device and history tags, 30 seconds each (`make fuzz`); seeds run in every `go test` |
| Native macOS service | PASS | macOS ARM64: install without `--start` (nothing runs; `doctor` warns), start, a command hook run while offline, `--replace` refusal for another profile file, `status`, `logs`, `test-event`, stop, restart, and uninstall keeping user data |
| Native Linux service | CI | Ubuntu 24.04 in the `Check` workflow, which must pass before a release is tagged |
| Reproducible release | PASS | Two `make dist` runs produce identical checksums; the extracted source archive passes the public-file check and the test suite |
| Interrupted work | PASS | A restart resumes pending checks without repeating a successful command; scheduled device reconciliation still notices a remote retirement |
| Notifications | PASS | Failure threshold, cooldown, one failure and one recovery notice per incident, literal arguments; a missing notification helper does not affect actions |
| Local events and simulation | PASS | Opt-in interface and resume events; `test-event` previews without side effects, and applied simulations refuse Azure before any command runs |
| Idle cost | PASS | 1,000 quiet polls of command and Azure profiles: zero allocations, state writes, subprocesses, checks, or notifications; real 60-second macOS samples |
| Idle and restart behavior | PASS | Over 130 state transitions, including errors, retries, local events, and restarts, the quiet-poll shortcut saves exactly when a full comparison would; a failed save blocks actions; `testing/synctest` timer tests cover long work, a late first tick, the full delay after work, and prompt cancellation |
| Azure reconciliation | PASS | Every pass rereads Azure; simulated peer enrollment, remote retirement, and unfinished writes keep their safety checks |
| Public files and recipes | PASS | Explicit file manifest, a private-profile leak canary, refusal of path traversal and symlinks in archives, fixed archive metadata; recipes tested with a fake provider CLI |
| Examples | PASS | The command example, the synthetic Azure example, and all three recipe profiles validate without credentials |

See [resource use](resources.md) for measured CPU, memory, size, method, and
limits. Current stable Go is the supported build and test toolchain. Go
dependencies remain standard-library-only; Python and the native service tools
are development and smoke-test utilities, not watcher dependencies.

## How the evidence is gathered

GitHub Actions runs the `Check` workflow on every push to `main`, on every pull
request, and weekly: `make check`, staticcheck, govulncheck, and the native
service smoke test on Ubuntu 24.04 and macOS 15 runners. The `CodeQL` workflow
analyzes the Go code and the workflows, and `Scorecard` publishes the
repository's OpenSSF Scorecard; Dependabot keeps pinned actions current. The
Actions tab shows current results; this record covers checks that need a
maintainer machine.

Native tests use temporary profiles and a deliberately failing local HTTPS
endpoint that triggers a harmless command. They do not call Azure. macOS test
installations isolate HOME; Linux tests use a disposable VM or user. Tests
check that uninstalling keeps the profile, the shared binary, state, history,
and unrelated units. Desktop banner visibility depends on OS
permissions and session settings; tests do not claim visual delivery on every
desktop.

Concurrent-client tests use independent engines, state, and history, and a
local HTTP API with a barrier that forces overlapping writes. They cover
keeping both current IPs, reusing PostgreSQL rule names, and retirement racing
with updates. They do not prove atomic real Azure writes or production
contention behavior.

## Release verification

See [releasing](releasing.md) for how releases are built and verified: two
builds with identical checksums, an extracted source archive that passes
`make check`, and a build provenance attestation for every asset.

Release binaries are cross-compiled. The macOS AMD64 binary has not been
exercised natively. Real Azure contention and throttling, Linux distributions
beyond those listed above, long-term battery use, signed or notarized
binaries, Windows, and public IPv6 tracking remain unverified or unsupported.
See [operating limits](operations.md#operating-limits).
