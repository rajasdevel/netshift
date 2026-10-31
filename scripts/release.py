#!/usr/bin/env python3
"""Reproducible public archives using Go and Python's standard library only.

Archive contents (tar bytes) are reproducible from the same source and Go
toolchain. The gzip stream comes from the host's zlib, so compressed bytes, and
therefore archive checksums, can differ between hosts whose binaries match;
compare the binary digests in BUILDINFO.json instead (docs/releasing.md).
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True  # Set before loading check-public.py below.

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('public_files', ROOT / 'scripts/check-public.py')
public_files = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public_files)
TARGETS = [('darwin', 'arm64'), ('darwin', 'amd64'), ('linux', 'arm64'), ('linux', 'amd64')]
RUNTIME_DOCS = {'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'CONTRIBUTING.md'}
BUILD_TIMEOUT = 600
VERSION_FILE = 'internal/version/version.go'


def archive(path, prefix, entries):
    """Write a gzip-compressed USTAR archive with fixed, machine-independent metadata."""
    names = [name for name, _, _ in entries]
    if len(names) != len(set(names)):
        raise ValueError('duplicate archive entry')
    with path.open('xb') as raw:
        # No file name, mtime 0 and a fixed level; GzipFile writes OS byte 255.
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, data, mode in sorted(entries, key=lambda entry: entry[0]):
                    if mode not in (0o644, 0o755):
                        raise ValueError('unexpected archive mode for ' + name)
                    item = tarfile.TarInfo(prefix + '/' + name)
                    item.type = tarfile.REGTYPE
                    item.size = len(data)
                    item.mode = mode
                    item.mtime = 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    tar.addfile(item, io.BytesIO(data))


def source_version():
    source = ROOT / VERSION_FILE
    found = re.search(r'^const Number = "([^"]+)"$', source.read_text(encoding='utf-8'), re.M)
    if found is None or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', found[1]):
        raise ValueError(f'{VERSION_FILE} must declare a valid release version')
    return found[1]


def source_digest(files):
    # Length-prefixed so that no two different file sets share an encoding.
    digest = hashlib.sha256()
    for name in files:
        data = (ROOT / name).read_bytes()
        digest.update(f'{name}\0{len(data)}\0'.encode() + data)
    return digest.hexdigest()


def publish(stage, out, names):
    """Copy staged files without replacing anything; remove partial output on failure."""
    created_dir = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    written = []
    try:
        for name in names:
            # 'x' refuses a file that appeared since the emptiness check.
            with (out / name).open('xb') as dst:
                written.append(out / name)
                dst.write((stage / name).read_bytes())
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        if created_dir:
            try:
                out.rmdir()
            except OSError:
                pass
        raise


def go_env():
    """The environment every release binary is built with."""
    env = os.environ.copy()
    env.update({'GOENV': 'off', 'GOFLAGS': '', 'GOEXPERIMENT': '', 'GOTOOLCHAIN': 'local',
                'GOWORK': 'off', 'GOFIPS140': 'off', 'CGO_ENABLED': '0',
                'GOAMD64': 'v1', 'GOARM64': 'v8.0'})
    return env


def build_binary(binary, goos, arch, env):
    """Build the release binary for goos/arch at path binary."""
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
                    '-o', str(binary), '.'], cwd=ROOT, env=dict(env, GOOS=goos, GOARCH=arch),
                   check=True, timeout=BUILD_TIMEOUT)


def build(output):
    files = public_files.check()
    version = source_version()
    out = Path(output).resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError(f'release output {out} must be a new or empty directory')
    names = [f'netshift_{version}_{goos}_{arch}.tar.gz' for goos, arch in TARGETS]
    names += [f'netshift_{version}_source.tar.gz', 'BUILDINFO.json', 'SHA256SUMS']
    env = go_env()
    # GOVERSION omits the host platform, so builds on macOS and Linux hosts agree.
    go_version = subprocess.run(['go', 'env', 'GOVERSION'], env=env, capture_output=True, text=True,
                                check=True, timeout=60).stdout.strip()
    info = {'version': version, 'go_version': go_version, 'source_sha256': source_digest(files),
            'cgo': False, 'buildvcs': False, 'trimpath': True, 'binaries': {}}
    runtime_docs = [name for name in files if name in RUNTIME_DOCS
                    or name.startswith(('docs/', 'config/', 'recipes/'))]
    with tempfile.TemporaryDirectory(prefix='netshift-release-') as tmp:
        stage = Path(tmp)
        for goos, arch in TARGETS:
            binary = stage / f'netshift-{goos}-{arch}'
            build_binary(binary, goos, arch, env)
            data = binary.read_bytes()
            info['binaries'][f'{goos}/{arch}'] = hashlib.sha256(data).hexdigest()
            entries = [('netshift', data, 0o755)]
            entries += [(name, (ROOT / name).read_bytes(), 0o644) for name in runtime_docs]
            stem = f'netshift_{version}_{goos}_{arch}'
            archive(stage / (stem + '.tar.gz'), stem, entries)
        stem = f'netshift_{version}_source'
        archive(stage / (stem + '.tar.gz'), stem,
                [(name, (ROOT / name).read_bytes(), 0o644) for name in files])
        (stage / 'BUILDINFO.json').write_text(json.dumps(info, indent=2, sort_keys=True) + '\n')
        payloads = sorted(name for name in names if name != 'SHA256SUMS')
        (stage / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256((stage / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in payloads))
        publish(stage, out, names)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', default='dist', help='new or empty release directory')
    args = parser.parse_args()
    try:
        out = build(args.output)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('release: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    print(f'Prepared {len(TARGETS)} binary archives, source archive, build info and SHA256SUMS in {out}')


if __name__ == '__main__':
    main()
