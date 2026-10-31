# Action recipes

These are opt-in examples. Copy a JSON profile to a private `*.local.json` file,
replace placeholder arguments and script paths, and run `validate`, `doctor`,
then `test-event` before enabling execution. `doctor` fails while any
`/absolute/path/to/` or `YOUR_` placeholder remains, or when a script path does
not exist; it does not detect `example.com` values, so replace those too. Use
absolute script paths: installed services run hooks from your home directory.
Scripts run through `/bin/sh`, so they need no executable bit.

| Recipe | Existing tool required | Trigger and effect |
| --- | --- | --- |
| `route53.json` | Authenticated AWS CLI | A confirmed IP change updates one configured DNS A record |
| `webhook.json` | curl | Sends the event JSON to your selected HTTPS endpoint |
| `restart-tunnel.json` | An existing launchd/systemd user tunnel service | Restarts that service on network recovery or a long polling gap, then checks its local TCP port |

For Linux, replace the tunnel label with the unit name, for example
`example-tunnel.service`. The script never creates SSH/VPN connections or
installs a service. A failed port check retries the check without restarting
the service again. Route 53 uses the AWS CLI's existing credentials; webhook
requests may use curl's existing `.netrc`. NetShift adds no credential store.

```sh
netshift --config route53.local.json test-event ip_changed --ip 8.8.8.8
```

This previews arguments/environment without network requests or writes. The
address above is a public resolver used as a stand-in: use an IP you own for actual DNS updates.
`test-event --apply` executes real command side effects with synthetic input;
use it only against a test destination you control. For a real network action,
`run ACTION --apply` confirms the current IP first. Services run with `--apply`.

Webhook payloads include public IPs and optional local interface addresses.
Choose a destination you trust and review what is sent. Retry semantics are
at least once: receiving endpoints should handle duplicates, and repeated
network recovery events can legitimately restart a configured service again.

CLI provider operations can change independently; review these scripts against
your tool version and permissions before deployment:
[Route 53 CLI](https://docs.aws.amazon.com/cli/latest/reference/route53/change-resource-record-sets.html),
[curl](https://curl.se/docs/manpage.html).
