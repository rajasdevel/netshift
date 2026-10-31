# Contributing

Thanks for helping improve NetShift! Bug reports, recipes, documentation fixes,
and focused pull requests are all welcome. For a new provider or a substantial
behavior change, please open an issue first so we can agree on the approach.
Small fixes can go straight to a pull request.

## Set up

You need the current stable Go toolchain (1.27 or later), Python 3.9 or later
for the packaging and smoke-test scripts, `make`, and `git`. No cloud account or
credentials are needed.

```sh
git clone https://github.com/rajasdevel/netshift.git
cd netshift
make check
```

NetShift itself uses only the Go standard library; please keep it that way.
Python is a development tool, not a runtime dependency. Only the current stable
Go release is supported, so older toolchains need no compatibility work.

## Quick checks

Run these before you open a pull request:

- `make check`: the full offline suite. It runs the public-file check, gofmt,
  the release-script tests, `go test`, the race detector, `go vet`, and
  validation of every example profile.
- `make lint`: `go vet` and staticcheck at the version pinned in the
  `Makefile`. The first run downloads staticcheck.

`make fmt` formats the Go code. Other targets:

- `make build` writes `bin/netshift`. A plain `go build` writes `./netshift` in
  the repository root instead; `.gitignore` ignores that file, so it cannot be
  committed by accident.
- `make smoke` runs the native service test described below.
- `make dist` builds reproducible release archives; see
  [releasing](docs/releasing.md).
- `make resources` measures an idle watcher. It is optional and makes real
  public-IP discovery requests.

## Code layout

`main.go` only calls `cli.Main`; everything else lives in packages under
`internal/`, each with its tests beside it. Imports point down the table:
a package uses only the packages listed below it.

| Package | What it owns |
| --- | --- |
| `cli` | Global options, the command table, help, and the generic commands (`validate`, `once`, `watch`, `run`, `status`, `logs`, `history`, `test-event`, `service`, `doctor`) |
| `doctor` | The read-only checks behind `netshift doctor` |
| `service` | launchd, systemd user, and Task Scheduler services: rendering, install, uninstall, control |
| `engine` | The watch loop, actions, retries, post-action checks, notifications, local events; the Azure action and its commands in `azure_*.go` |
| `discovery` | Public-IP discovery and the interface snapshot |
| `store` | The state file, its lock, and the append-only history |
| `config` | The profile format, defaults, and validation |
| `cmdline` | Option parsing and usage errors shared by every command |
| `proc` | Running programs with timeouts, bounded output, and process groups or Job Objects; safe batch-file command lines |
| `eventlog` | The JSON event log and its rotation |
| `fsx` | Bounded reads, no-follow opens, atomic writes, directory syncs, and locks |
| `version` | The release version |

Keep the engine's quiet path free of allocations, writes, and subprocesses;
`go test -run '^$' -bench '^BenchmarkQuiet' -benchmem ./internal/engine`
checks it.

## Public files

`release-files.txt` lists every public file in the repository, in sorted order.
When you add, rename, or remove a file, update the list in the same pull
request. `make check` fails if git would publish a file that is not listed, if
a listed file is missing or ignored, or if a public file appears to contain a
credential, a non-example IP address, or an identifier from a private profile.

Keep personal material out of the repository: name private profiles
`*.local.json` and keep notes in `.local/`. Both are ignored by git and never
enter a release.

## Testing safely

- Tests use synthetic resource IDs and local fake Azure APIs. Do not use real
  Azure credentials, subscriptions, hostnames, or IP histories in tests, and
  never run cloud mutations as tests.
- `make smoke` installs a real launchd or systemd user service with a unique
  profile, triggers a harmless command hook through a deliberately failing
  local endpoint, and removes what it created. It needs a macOS GUI session or
  a Linux systemd user manager. On macOS it uses a temporary HOME; on Linux it
  refuses to run over an existing NetShift installation, so use a disposable VM
  or user. It never contacts Azure. Cross-compiling is not a substitute.

## Windows

Windows support is experimental and is verified only on GitHub-hosted
`windows-latest` runners; no maintainer runs Windows. Platform code lives in
`*_windows.go` files in `fsx`, `proc`, `store`, and `cli`, and calls Windows
through `syscall` and `syscall.NewLazyDLL`, never `golang.org/x/sys`. The
service package renders and controls the Task Scheduler task from portable
code, so its tests run everywhere with a fake `schtasks.exe`.

- `make lint` also runs `go vet` and staticcheck with `GOOS=windows`.
- Tests that need `/bin/sh` or Unix permissions skip on Windows or have a
  Windows counterpart; prefer a counterpart.
- The `Check` workflow runs `scripts/native-smoke.py` on Windows, which
  registers a real task with a temporary `%LOCALAPPDATA%` and removes it. Do
  not run it on your own Windows account unless you accept a test task
  briefly appearing in Task Scheduler.

## Change boundaries

- Keep `user@host` histories and deterministic PostgreSQL rule names separate.
- Preserve unknown sources, unrelated metadata, and all immutable rule fields.
- Keep cloud changes behind `--apply` and native service activation behind `--start`.
- Save intent before a mutation, verify its result, and keep recovery evidence.
- Keep retirement explicit. Do not add automatic expiry or remove tombstones in watch.
- Treat profiles as trusted executable policy and cloud records as validated input.
- Do not promise atomic cloud updates. Test interleaving and interrupted operations.
- Keep disabled features inactive. When changing the poll loop, add regression
  checks that quiet polls write nothing and start no helpers or probes.
- Measure the watcher separately from external CLIs in resource measurements.

## Pull requests

Describe what triggered the change, how behavior changes, and how you
validated it. Add a regression test for a behavior change when it demonstrates
a failure that matters, and update the [operations guide](docs/operations.md)
for schema, ownership, or lifecycle changes. Contributions are accepted under
the project's [MIT license](LICENSE).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
