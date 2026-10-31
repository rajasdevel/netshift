# Security policy

## Supported versions

Security fixes go into the next release; they are not backported.

| Version | Receives security fixes |
| --- | --- |
| Latest release | Yes |
| Earlier releases and unreleased builds | No; upgrade to the latest release |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting form](https://github.com/rajasdevel/netshift/security/advisories/new),
also reachable from the repository's **Security** tab. Please do not open a
public issue, pull request, or discussion about a suspected vulnerability. If
you cannot use the form, contact the maintainer privately through the contact
listed on their GitHub profile and ask for a private channel, without including
details.

A useful report includes:

- the NetShift version (`netshift --version`) and operating system;
- the affected command or operation, and the boundary you expected it to keep;
- a minimal reproduction that uses synthetic resources, local fixtures, or fake
  Azure responses.

Never include credentials, real profiles, resource IDs, public-IP history, or
unredacted logs, and never probe or modify Azure resources that are not yours.

This is a volunteer-maintained project, so no response time is guaranteed. The
fix and its disclosure are coordinated in the private advisory.

## Security model

- NetShift runs the commands in a profile as the local user, so a profile can
  run any command as you. Run only profiles you wrote or reviewed.
- The built-in Azure action changes access rules with the privileges of your
  installed Azure CLI. Azure RBAC and the local OS account are the
  access-control boundaries; a device label is not authentication.
- Write access to a managed NSG's `netshift.*` tags is effectively network
  access: a principal that can add a device record there can get its address
  allowed by every enrolled client. Retirement does not change records it
  cannot read or the addresses they mention; if that leaves an address of the
  retired device allowed, it fails with `retired_address_retained` instead of
  reporting success. Grant tag write only to principals you would also trust
  to edit the rules.

The [operations guide](docs/operations.md) describes the trust model and the
known concurrency and retirement limits.
