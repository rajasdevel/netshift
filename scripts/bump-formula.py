#!/usr/bin/env python3
"""Point the Homebrew formula at a NetShift release, using the release's SHA256SUMS.

Rewrites the four archive URLs and checksums in the tap's Formula/netshift.rb
and leaves the rest of the formula unchanged. It refuses a prerelease, a
downgrade, and a formula of any other shape (docs/releasing.md).
"""
from pathlib import Path
import argparse
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

sys.dont_write_bytecode = True

RELEASES = 'https://github.com/rajasdevel/netshift/releases/download'
# The macOS and Linux archives release.py builds (test-release.py checks that
# the two lists agree), and the Homebrew blocks each one belongs in.
TARGETS = {
    ('darwin', 'arm64'): ('on_macos', 'on_arm'),
    ('darwin', 'amd64'): ('on_macos', 'on_intel'),
    ('linux', 'arm64'): ('on_linux', 'on_arm'),
    ('linux', 'amd64'): ('on_linux', 'on_intel'),
}
STABLE = re.compile(r'(\d+)\.(\d+)\.(\d+)')
SUMS_LIMIT = 64 * 1024
DOWNLOAD_TIMEOUT = 30
SUM_LINE = re.compile(r'([0-9a-f]{64}) [ *](\S+)')
ARCHIVE = re.compile(
    r'^(?P<indent>[ \t]*)url "' + re.escape(RELEASES) + r'/v(?P<tag>[^/"]+)/'
    r'netshift_(?P<version>[^_/"]+)_(?P<goos>[a-z0-9]+)_(?P<arch>[a-z0-9]+)\.tar\.gz"\n'
    r'(?P=indent)sha256 "[0-9a-f]{64}"$', re.M)
BLOCK = re.compile(r'^[ \t]*(on_macos|on_linux|on_arm|on_intel) do$', re.M)


def stable_version(text):
    version = text.removeprefix('v')
    if STABLE.fullmatch(version) is None:
        raise ValueError(f'{text} is not a stable release version (MAJOR.MINOR.PATCH); '
                         'the tap does not ship prereleases')
    return version


def version_key(version):
    return tuple(int(part) for part in STABLE.fullmatch(version).groups())


def archive_url(version, goos, arch):
    return f'{RELEASES}/v{version}/netshift_{version}_{goos}_{arch}.tar.gz'


def download(url, opener=urllib.request.urlopen):
    request = urllib.request.Request(url, headers={'User-Agent': 'netshift-bump-formula'})
    try:
        with opener(request, timeout=DOWNLOAD_TIMEOUT) as response:
            data = response.read(SUMS_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError(f'cannot download {url}: HTTP {exc.code}; is the release published?') from None
    except (urllib.error.URLError, OSError) as exc:
        raise ValueError(f'cannot download {url}: {getattr(exc, "reason", exc)}') from None
    if len(data) > SUMS_LIMIT:
        raise ValueError(f'{url} is larger than {SUMS_LIMIT} bytes')
    return data.decode('utf-8')


def read_sums(path):
    with open(path, 'rb') as source:
        data = source.read(SUMS_LIMIT + 1)
    if len(data) > SUMS_LIMIT:
        raise ValueError(f'{path} is larger than {SUMS_LIMIT} bytes')
    return data.decode('utf-8')


def parse_sums(text, version):
    """Return {(goos, arch): sha256} for the release's binary archives."""
    digests = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        found = SUM_LINE.fullmatch(line)
        if found is None:
            raise ValueError(f'SHA256SUMS line {number} is not "<sha256>  <file>"')
        digest, name = found.groups()
        if name in digests:
            raise ValueError(f'SHA256SUMS lists {name} more than once')
        digests[name] = digest
    result = {}
    for goos, arch in TARGETS:
        name = archive_url(version, goos, arch).rsplit('/', 1)[1]
        if name not in digests:
            raise ValueError(f'SHA256SUMS has no checksum for {name}')
        result[goos, arch] = digests[name]
    return result


def rewrite(text, version, digests):
    """Return (current version, formula text pointing at version)."""
    if re.search(r'^[ \t]*version ', text, re.M):
        raise ValueError('the formula sets version explicitly; remove it, Homebrew reads it from the URL')
    found = list(ARCHIVE.finditer(text))
    urls = len(re.findall(r'^[ \t]*url ', text, re.M)) - len(re.findall(r'^[ \t]*url :stable$', text, re.M))
    sums = len(re.findall(r'^[ \t]*sha256 ', text, re.M))
    if sorted((m['goos'], m['arch']) for m in found) != sorted(TARGETS) or urls != len(TARGETS) \
            or sums != len(TARGETS):
        raise ValueError('the formula must have exactly one release archive url, followed by its '
                         'sha256, for each of ' + ', '.join(f'{g}/{a}' for g, a in sorted(TARGETS)))
    current = {m['tag'] for m in found} | {m['version'] for m in found}
    if len(current) != 1 or STABLE.fullmatch(next(iter(current))) is None:
        raise ValueError('the formula archives do not share one stable version')
    current = current.pop()
    if version_key(version) < version_key(current):
        raise ValueError(f'refusing to downgrade the formula from {current} to {version}')
    pieces, end = [], 0
    for match in found:
        target = match['goos'], match['arch']
        blocks = BLOCK.findall(text, 0, match.start())
        placed = ([b for b in blocks if b in ('on_macos', 'on_linux')][-1:]
                  + [b for b in blocks if b in ('on_arm', 'on_intel')][-1:])
        if tuple(placed) != TARGETS[target]:
            raise ValueError(f'the {"/".join(target)} archive must be inside '
                             f'{" > ".join(TARGETS[target])}')
        indent = match['indent']
        pieces += [text[end:match.start()], f'{indent}url "{archive_url(version, *target)}"\n'
                   f'{indent}sha256 "{digests[target]}"']
        end = match.end()
    pieces.append(text[end:])
    return current, ''.join(pieces)


def replace_file(path, text):
    """Write text to path atomically, keeping its permissions."""
    mode = path.stat().st_mode & 0o777
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as out:
            out.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def bump(version, formula, sums=None, opener=urllib.request.urlopen):
    """Rewrite formula for version; return (previous version, changed)."""
    version = stable_version(version)
    if sums is None:
        text = download(f'{RELEASES}/v{version}/SHA256SUMS', opener)
    else:
        text = read_sums(sums)
    digests = parse_sums(text, version)
    formula = Path(formula).resolve()
    original = formula.read_text(encoding='utf-8')
    previous, updated = rewrite(original, version, digests)
    if updated != original:
        replace_file(formula, updated)
    return previous, updated != original


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('version', help='published release version, such as 0.7.0')
    parser.add_argument('formula', help="path to the tap's Formula/netshift.rb")
    parser.add_argument('--sums', metavar='FILE',
                        help="read SHA256SUMS from FILE instead of downloading the release's copy")
    args = parser.parse_args(argv)
    try:
        previous, changed = bump(args.version, args.formula, args.sums)
    except (ValueError, OSError) as exc:
        print('bump-formula: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    version = stable_version(args.version)
    if changed:
        print(f'Updated {args.formula} from {previous} to {version}')
    else:
        print(f'{args.formula} already points at {version}')


if __name__ == '__main__':
    main()
