# Building and verifying releases

NetShift releases are built by the tag workflow in
`.github/workflows/release.yml`, from the public repository
`github.com/rajasdevel/netshift`, under the MIT license. Every build step can
also be run locally.

## Verify a download

Each release contains six binary archives (macOS, Linux, and Windows on
ARM64 and AMD64; Windows archives are `.zip` files), a source archive,
`BUILDINFO.json`, and `SHA256SUMS`. Check the archives against `SHA256SUMS`:

```sh
# macOS
shasum -a 256 -c SHA256SUMS
# Linux
sha256sum --check SHA256SUMS
```

On Windows, compare `(Get-FileHash netshift_<version>_windows_amd64.zip).Hash`
in PowerShell with the archive's line in `SHA256SUMS` (the hashes match
ignoring case).

Checksums detect corruption; they do not show who built the files. Every
release asset also carries a signed build provenance attestation, which shows
that the release workflow built it from this repository. Check it with the
GitHub CLI:

```sh
gh attestation verify netshift_<version>_darwin_arm64.tar.gz \
  --repo rajasdevel/netshift \
  --signer-workflow rajasdevel/netshift/.github/workflows/release.yml
```

Release binaries are not code-signed or notarized. If your platform policy
requires it, build from source instead.

## Build release archives

Use the current stable Go toolchain (1.27 or later) and Python 3.9 or later:

```sh
make check
make dist OUTPUT=dist/first
make dist OUTPUT=dist/second
diff dist/first/SHA256SUMS dist/second/SHA256SUMS
```

`make dist` refuses an output directory that already contains files, and it
removes its partial output if it fails.

Each binary archive holds the `netshift` executable, the license, the guides,
the example profiles, and the recipes. The source archive holds exactly the
files in `release-files.txt` and no Git history; it builds and passes
`make check` after extraction. `BUILDINFO.json` records the version, the Go
version, a digest of the source files, and the SHA-256 digest of each binary.
`SHA256SUMS` covers the archives and `BUILDINFO.json`.

## Reproducibility

The build disables cgo and VCS stamping, trims paths, uses only the local Go
toolchain with fixed `GOAMD64`/`GOARM64` levels, and ignores `go.work`. The
archives contain sorted entries with fixed metadata: owner and group 0 with
empty names, modification time 0, and mode 0644, or 0755 for the executable.
The gzip header records no file name, modification time 0, and an unknown
operating system.

On one machine, two builds of the same source produce identical files; the
release workflow checks this on every tag. Across machines, **compare the
binary digests in `BUILDINFO.json`, not the archive checksums.** The compressed
bytes come from the zlib library linked into the host's Python, so archive
checksums can differ between hosts whose binaries are identical. To check a
release on your own machine, install the `go_version` it records and run:

```sh
make dist OUTPUT=/tmp/netshift-rebuild
diff /tmp/netshift-rebuild/BUILDINFO.json path/to/release/BUILDINFO.json
```

Matching `BUILDINFO.json` files mean the same source produced the same
binaries. The uncompressed tar stream does not depend on zlib, so
`gzip -dc ARCHIVE | shasum -a 256` compares a whole archive's contents across
hosts. Different Go versions produce different binaries.

## The public file set

`release-files.txt` lists every public file. `scripts/check-public.py` (part
of `make check`) fails when:

- a file outside the ignored private and build paths is not listed, or a listed
  path is unsafe, private, a symlink, or missing;
- in a git work tree, the files git tracks or would add
  (`git ls-files --cached --others --exclude-standard`) differ from the list,
  `.gitignore` stops ignoring a private or build canary such as
  `config/x.local.json`, `.env`, `dist/`, or a root `netshift` binary, or
  `.gitignore` hides a listed file;
- a listed file contains a private key, a common token format, a home
  directory path, a non-synthetic UUID, a global IPv4 address outside the
  documentation ranges and example resolvers, or an identifier from a local
  `*.local.json` profile.

Failures name the file and the kind of finding, never the matched value. The
check supplements human review; it is not a complete secret scanner.

## The release workflow

Pushing a tag `v<version>` runs the workflow, which:

1. runs the full `Check` workflow on Linux, macOS, and Windows;
2. requires the tag to match `Number` in `internal/version/version.go`;
3. takes the release notes from the `## <version>` section of `CHANGELOG.md`,
   and fails if that section is missing or empty;
4. builds the release twice, requires identical `SHA256SUMS`, and verifies them;
5. creates build provenance attestations for every asset;
6. uploads the assets as a workflow artifact and creates a **draft** release,
   marked as a prerelease when the version contains `-`.

The workflow never publishes a release, and it does not replace an existing
release with the same tag: delete a stale draft before re-running. Only the
release job may write to the repository or request a signing token; every
other job reads only. Actions are pinned to full commit SHAs.

## Maintainer checklist

Repository settings, once:

- Enable **private vulnerability reporting**, Dependabot alerts and security
  updates, and secret scanning with push protection (Settings → Code
  security). Leave CodeQL "Default setup" off: the `CodeQL` workflow uploads
  its own results, and GitHub rejects those while default setup is on.
- Protect `main` with a branch ruleset (not classic branch protection, which
  Scorecard cannot read with the default token) that requires pull requests
  and the `Check` and `CodeQL` jobs: `check (ubuntu-24.04)`,
  `check (macos-15)`, `check (windows-latest)`, `analyze (go)`, and
  `analyze (actions)`. With one
  maintainer, leave "Require review from Code Owners" off.
- Protect `v*` tags with a tag ruleset so only maintainers can create, move, or
  delete them.
- Set the default workflow token permissions to read-only (Settings → Actions →
  General); the release job requests its own write permissions.
- List a public contact on the maintainer's GitHub profile; the security
  policy points to it.

For each release:

1. Update `Number` in `internal/version/version.go` and the matching `CHANGELOG.md` heading,
   `## <version> — <YYYY-MM-DD>`, in the same pull request.
2. Run `make check` and `make lint`, and run `make smoke` on macOS and Linux.
   Windows is checked only by the `Check` workflow. Record the results in
   [validation](validation.md).
3. After `Check` passes on `main`, tag that commit and push the tag:
   `git tag v<version> && git push origin v<version>`.
4. Review the draft: the eight assets plus `SHA256SUMS`, the notes, and the
   prerelease flag. Download an archive and verify its checksum and
   attestation as described in [Verify a download](#verify-a-download).
5. Publish the draft.
