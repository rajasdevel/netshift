#!/usr/bin/env python3
"""Check that the public file set matches release-files.txt and leaks nothing private.

Failures name the file and the kind of finding, never the matched value.
"""
from pathlib import Path, PurePosixPath
import ipaddress
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
# SKIP_DIRS and private_name mirror .gitignore. They are the view of "private"
# used without git; in a git work tree, check_git also asks git directly.
SKIP_DIRS = {'.git', '.local', 'bin', 'dist', '__pycache__', '.idea', '.vscode'}
# Paths .gitignore must ignore. They need not exist. A root `netshift` is the
# output of a plain `go build`.
IGNORED_CANARIES = [
    'config/x.local.json', 'x.local.md', '.local/x', 'dist/x', 'bin/x', 'netshift',
    'x.history.jsonl', '.env', '.env.local', '.envrc', 'coverage.out', '.DS_Store',
    'scripts/__pycache__/x.pyc', '.idea/x', '.vscode/x', 'x.swp',
]
# Paths .gitignore must not ignore, in addition to every manifest entry.
PUBLIC_CANARIES = ['.env.example', 'docs/netshift']
GIT_TIMEOUT = 30
UUID = re.compile(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b')
SYNTHETIC_UUID = '00000000-0000-0000-0000-000000000001'
# Well-known GUIDs that Windows defines, not identifiers from a profile.
# FOLDERID_System is part of Windows PowerShell's app ID, which shows toasts.
WINDOWS_GUIDS = {'1ac14e77-02e7-4e5d-b744-2eb1ae5198b7'}
PATTERNS = {
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'GitHub token': re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}'),
    'AWS access key': re.compile(r'AKIA[A-Z0-9]{16}'),
    # /home/sam/ is the synthetic home directory used in tests.
    'embedded home path': re.compile(r'/Users/[A-Za-z0-9_.-]+/|/home/(?!sam/)[A-Za-z0-9_.-]+/'),
}
IPV4 = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')
# Public examples may use documentation ranges (never global) or these
# well-known public resolvers. Any other global IPv4 may be a real address.
EXAMPLE_NETWORKS = [ipaddress.ip_network(n) for n in (
    '1.0.0.0/24', '1.1.1.0/24', '4.2.2.0/24', '4.4.4.0/24', '8.8.4.0/24',
    '8.8.8.0/24', '9.9.9.0/24', '208.67.222.0/24')]


def private_name(path):
    """Mirror the file patterns in .gitignore (directories are in SKIP_DIRS)."""
    name = path.name
    return ('.local.' in name
            or name.endswith(('.history.jsonl', '.test', '.out', '.coverprofile',
                              '.pyc', '.swp', '.swo', '~'))
            or name in {'.DS_Store', 'coverage.html', 'go.work', 'go.work.sum'}
            or (name.startswith('.env') and name != '.env.example'))


def manifest_files(root=ROOT):
    entries = [line.strip() for line in (root / 'release-files.txt').read_text().splitlines()
               if line.strip() and not line.startswith('#')]
    if len(entries) != len(set(entries)):
        raise ValueError('duplicate release manifest entries')
    for entry in entries:
        rel = PurePosixPath(entry)
        if (rel.is_absolute() or '..' in rel.parts or '\\' in entry or entry == 'netshift'
                or any(p in SKIP_DIRS for p in rel.parts) or private_name(rel)):
            raise ValueError('unsafe/private release path: ' + entry)
        path = root / entry
        components = [p for p in [path, *path.parents] if p != root.parent and root in [p, *p.parents]]
        if not path.is_file() or any(p.is_symlink() for p in components):
            raise ValueError('release entry must be a regular file with no symlink components: ' + entry)
    return sorted(entries)


def visible_files(root=ROOT):
    result = set()
    def visit(directory):
        for path in directory.iterdir():
            if path.name in SKIP_DIRS or private_name(path) or path == root / 'netshift':
                continue  # ./netshift is the output of a plain `go build`.
            if path.is_symlink():
                result.add(path.relative_to(root).as_posix())
            elif path.is_dir():
                visit(path)
            elif path.is_file():
                result.add(path.relative_to(root).as_posix())
    visit(root)
    return result


def git(root, *args, stdin=None):
    """Run git in root with only the repository's own ignore rules."""
    # Inherited GIT_DIR/GIT_WORK_TREE (as in a hook) could point at another repository.
    env = {k: v for k, v in os.environ.items() if k not in ('GIT_DIR', 'GIT_WORK_TREE')}
    try:
        result = subprocess.run(
            ['git', '-C', str(root), '-c', 'core.excludesFile=' + os.devnull, *args],
            input=stdin, capture_output=True, env=env, timeout=GIT_TIMEOUT)
    except FileNotFoundError:
        raise ValueError('git is required to check a git work tree') from None
    except subprocess.TimeoutExpired:
        raise ValueError(f'git {args[0]} did not finish within {GIT_TIMEOUT} seconds') from None
    # check-ignore exits 1 when no path is ignored.
    if result.returncode and not (args[0] == 'check-ignore' and result.returncode == 1):
        detail = result.stderr.decode(errors='replace').strip()[:500]
        raise ValueError(f'git {args[0]} failed' + (': ' + detail if detail else ''))
    return result


def git_files(root=ROOT):
    """Return the files git would publish, or None when root has no git metadata."""
    if not (root / '.git').exists():
        return None  # For example, an extracted source archive.
    top = os.fsdecode(git(root, 'rev-parse', '--show-toplevel').stdout.strip())
    if Path(top).resolve() != root.resolve():
        raise ValueError('git does not treat the repository root as its work tree root')
    listed = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').stdout
    return {os.fsdecode(p) for p in listed.split(b'\0') if p}


def ignored(root, paths):
    """Return the subset of paths that the ignore rules match, tracked or not."""
    result = git(root, 'check-ignore', '--no-index', '-z', '--stdin',
                 stdin=b''.join(os.fsencode(p) + b'\0' for p in paths))
    return {os.fsdecode(p) for p in result.stdout.split(b'\0') if p}


def check_git(root, paths):
    """In a git work tree, git's publishable file set must equal the manifest."""
    published = git_files(root)
    if published is None:
        return
    problems = []
    unlisted = sorted(published - set(paths))
    if unlisted:
        problems.append('git tracks or would add files missing from the release manifest: '
                        + ', '.join(unlisted))
    unseen = sorted(set(paths) - published)
    if unseen:
        problems.append('release manifest lists files git ignores or cannot see: ' + ', '.join(unseen))
    exposed = sorted(set(IGNORED_CANARIES) - ignored(root, IGNORED_CANARIES))
    if exposed:
        problems.append('.gitignore does not ignore private/build canaries: ' + ', '.join(exposed))
    hidden = sorted(ignored(root, PUBLIC_CANARIES + paths))
    if hidden:
        problems.append('.gitignore ignores public paths: ' + ', '.join(hidden))
    if problems:
        raise ValueError('\n'.join(problems))


def unexpected_public_ip(text):
    for match in IPV4.findall(text):
        try:
            ip = ipaddress.ip_address(match)
        except ValueError:
            continue
        if ip.is_global and not ip.is_multicast and not any(ip in n for n in EXAMPLE_NETWORKS):
            return True
    return False


def private_identifiers(root=ROOT):
    # Optional local check: private profiles never enter source archives or CI.
    selected = {'subscription', 'resource_group', 'nsg', 'server', 'identity',
                'legacy_identity', 'seed_identity', 'bootstrap_ip', 'known_ips',
                'rule', 'address', 'destination', 'destinations', 'legacy_tag'}
    values = set()
    def walk(value, key=''):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, list):
            for v in value:
                walk(v, key)
        elif key in selected and isinstance(value, str) and len(value) >= 6:
            values.add(value.lower())
    for path in sorted({*root.glob('*.local.json'), *(root / 'config').glob('*.local.json')}):
        try:
            walk(json.loads(path.read_text(encoding='utf-8')))
        except ValueError:
            # Name the file only; never echo any of its content.
            raise ValueError('cannot parse private profile ' + path.relative_to(root).as_posix()) from None
    return values


def check(root=ROOT):
    paths = manifest_files(root)
    extra = visible_files(root) - set(paths)
    if extra:
        raise ValueError('public files missing from release manifest: ' + ', '.join(sorted(extra)))
    check_git(root, paths)
    sensitive = private_identifiers(root)
    failures = []
    for name in paths:
        try:
            text = (root / name).read_text(encoding='utf-8')
        except UnicodeDecodeError:
            failures.append(name + ': not UTF-8 text')
            continue
        kinds = [kind for kind, regex in PATTERNS.items() if regex.search(text)]
        if any(value.lower() not in WINDOWS_GUIDS | {SYNTHETIC_UUID} for value in UUID.findall(text)):
            kinds.append('non-synthetic subscription/UUID')
        if unexpected_public_ip(text):
            kinds.append('public IPv4 outside documentation ranges and example resolvers')
        lowered = text.lower()
        if any(value in lowered for value in sensitive):
            kinds.append('identifier from a private local profile')
        if kinds:
            failures.append(name + ': ' + ', '.join(kinds))
    if failures:
        raise ValueError('\n'.join(failures))
    return paths


if __name__ == '__main__':
    try:
        paths = check()
        print(f'Public file check passed: {len(paths)} explicit files; private files excluded.')
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
