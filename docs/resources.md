# Resource use

NetShift is one Go binary built from the standard library. The watcher runs a
single sequential poll loop. There is no sidecar, web UI, database, telemetry,
or resident helper; the native service manager owns the process lifetime.

## Work performed

- **Unchanged polls.** With the default 30-second interval (configurable from 5
  seconds to a day), an unchanged IP needs one small HTTPS request per poll. A quiet poll writes no state, logs
  nothing, starts no process, and runs no reachability check. The engine's
  quiet path allocates no memory.
- **Confirming a change.** A new address needs agreement from two distinct
  configured sources and, in watch mode, two consecutive observations by
  default. Discovery uses at most four endpoints with bounded timeouts.
- **Connections.** A discovery connection is reused for up to five minutes,
  counting time asleep, then reopened, because an established connection can
  keep an old route (and report an old public IP) after the default route
  moves. TCP keepalive probes
  are disabled. Wire bytes depend on TLS and proxies.
- **State.** Changes are written atomically and synced. The audit history is
  append-only and grows with external operations, not with unchanged polls.
- **Azure.** Device mode reconciles shared state every 30 minutes by default
  (`devices.reconcile_seconds`).
  Those Azure CLI processes and cloud calls have their own cost and are not
  part of the idle measurements below.
- **Optional features.** Notifications start a native helper only when a
  failure or recovery notice is due. Post-action checks run only after actions
  or in `doctor --checks`. Local event sources reuse the poll timer and add no
  network requests. `logs --follow` runs one reader process while it is open.
- **Logs.** macOS event logs rotate at 1 MiB plus one backup; Linux uses the
  journal's retention.

## Measurements

Each sample ran for 60 seconds with five-second polling (six times the default
rate), with notifications and both local event sources enabled. CPU is
cumulative process CPU divided by wall time, as a percentage of one core,
including startup.

| Platform | CPU of one core | Median RSS | Peak RSS |
| --- | --- | --- | --- |
| macOS ARM64 | 0.038% | 16.7 MiB | 17.2 MiB |
| Debian 12 ARM64 | 0.053% | 13.5 MiB | 16.4 MiB |

Resident memory varies by a few MiB between runs, because Go's garbage
collector lets short-lived allocations accumulate before collecting them;
macOS samples have ranged from 13 to 17 MiB. Lowering `GOGC` did not reduce
it. Release binaries are about 7 MiB.

For scale, a 20-line Go program that only fetches one HTTPS URL every five
seconds, run side by side with NetShift on macOS ARM64, used 12–14 MiB and a
5.6 MB binary, against NetShift's 13–16 MiB and 7.5 MB. Most of the footprint
is the Go runtime and TLS stack that any Go HTTPS client carries.

Every sample had zero state writes, action executions, and log lines while the
network was unchanged. Engine microbenchmarks, which exclude HTTP and cloud
work, show zero allocations per quiet poll. Short samples are evidence for the
measured configuration, not guarantees about every OS, network, user script,
or long-term battery use.

## Reproduce measurements

```sh
make check
make resources        # the measurement above: 60 seconds, 5-second polls
# Compare with another build, 60 seconds each:
python3 scripts/resource-smoke.py --binary bin/netshift \
  --baseline /absolute/path/to/other-netshift --seconds 60 --interval 5
# The engine's quiet-poll cost without HTTP or cloud work:
go test -run '^$' -bench '^BenchmarkQuiet' -benchmem ./internal/engine
```

The resource smoke test uses disposable profiles and state, makes ordinary
public-IP requests, and runs only a no-op action. It measures process CPU,
resident memory, state-file stability, and event/action counts, and fails if
the network or state changes during the sample. It never calls a cloud CLI,
installs a service, or publishes identifiers.
