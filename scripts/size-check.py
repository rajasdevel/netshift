#!/usr/bin/env python3
"""Fail when a release binary is more than limit_percent larger than its baseline.

The baseline in scripts/size-baseline.json records the v0.6.0 release binaries.
Growth is measured against it, not against the previous commit, so small
increases across many changes still add up. Raise the baseline only on purpose,
with --update, in a reviewed pull request.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # Set before loading release.py below.

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / 'scripts/size-baseline.json'
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def measure():
    """Build every release target and return its size in bytes and the Go version."""
    env = release.go_env()
    go_version = subprocess.run(['go', 'env', 'GOVERSION'], env=env, capture_output=True,
                                text=True, check=True, timeout=60).stdout.strip()
    sizes = {}
    with tempfile.TemporaryDirectory(prefix='netshift-size-') as tmp:
        for goos, arch in release.TARGETS:
            binary = Path(tmp) / f'netshift-{goos}-{arch}'
            release.build_binary(binary, goos, arch, env)
            sizes[f'{goos}/{arch}'] = binary.stat().st_size
    return sizes, go_version


def compare(baseline, sizes):
    """Return one row per baseline target and the targets over the limit or missing."""
    limit = baseline['limit_percent']
    rows, failures = [], []
    for target, base in sorted(baseline['binaries'].items()):
        size = sizes.get(target)
        if size is None:
            rows.append((target, base, None, None, 'missing'))
            failures.append(target)
            continue
        # Integer arithmetic: over means size > base * (1 + limit/100).
        over = size * 100 > base * (100 + limit)
        rows.append((target, base, size, (size - base) * 100 / base, 'over' if over else 'ok'))
        if over:
            failures.append(target)
    return rows, failures


def report(rows, limit, go_version, baseline_go):
    """A Markdown table of the comparison."""
    lines = [f'Binary sizes against the baseline (limit: +{limit}%; built with {go_version}, '
             f'baseline {baseline_go})', '',
             '| Target | Baseline | Now | Change | Result |', '| --- | ---: | ---: | ---: | --- |']
    for target, base, size, growth, result in rows:
        now = '-' if size is None else f'{size:,}'
        change = '-' if growth is None else f'{growth:+.2f}%'
        lines.append(f'| {target} | {base:,} | {now} | {change} | {result} |')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    parser.add_argument('--update', action='store_true',
                        help='record the current sizes as the new baseline (a deliberate change)')
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text())
    sizes, go_version = measure()
    if args.update:
        baseline.update(binaries=sizes, measured_with=go_version)
        args.baseline.write_text(json.dumps(baseline, indent=2, sort_keys=True) + '\n')
        print(f'Updated {args.baseline.name} with sizes built by {go_version}.')
        return 0
    rows, failures = compare(baseline, sizes)
    text = report(rows, baseline['limit_percent'], go_version, baseline.get('measured_with', 'unknown'))
    print(text, end='')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as out:
            out.write(text)
    if failures:
        print(f'Binaries over the size limit: {", ".join(failures)}. Shrink them, or raise the '
              'baseline deliberately with scripts/size-check.py --update.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
