#!/usr/bin/env python3
"""Measure a real idle watcher; never invoke cloud actions or publish machine data."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True


def stop_with_usage(process):
    try:
        os.kill(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 10
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return usage
        if time.monotonic() >= deadline:
            os.kill(process.pid, signal.SIGKILL)
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
            raise RuntimeError('watcher did not stop within ten seconds')
        time.sleep(0.05)


def measure(binary, label, seconds, interval):
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix='netshift-resource-') as temp:
        root = Path(temp)
        config, state, log = root / 'profile.json', root / 'state.json', root / 'events.log'
        # Optional local event sources and notifications are on, the costliest
        # idle configuration.
        monitor = {'interval_seconds': interval, 'timeout_seconds': 5,
                   'interface_changes': True, 'resume_after_seconds': 300}
        profile = {'version': 1, 'profile': 'resource-smoke', 'monitor': monitor,
                   'notifications': {'enabled': True},
                   'actions': {'noop': {'type': 'command', 'timeout_seconds': 5,
                                        'command': ['/usr/bin/true']}}}
        config.write_text(json.dumps(profile))
        command = [binary, '--config', str(config), '--state', str(state)]
        subprocess.run(command + ['once', '--apply'], capture_output=True, check=True, timeout=60)
        before = (hashlib.sha256(state.read_bytes()).hexdigest(), state.stat().st_mtime_ns)
        samples = []
        with log.open('w') as output:
            process = subprocess.Popen(command + ['watch', '--apply'], stdout=output, stderr=subprocess.STDOUT)
            start = time.monotonic()
            try:
                while time.monotonic() - start < seconds:
                    time.sleep(min(5, max(0, seconds - (time.monotonic() - start))))
                    raw = subprocess.check_output(['ps', '-p', str(process.pid), '-o', 'rss='], text=True, timeout=5)
                    samples.append(int(raw.strip()))
            finally:
                usage = stop_with_usage(process)
        elapsed = time.monotonic() - start
        if process.returncode != 0:
            raise RuntimeError('idle watcher exited unsuccessfully; inspect locally before retrying')
        after = (hashlib.sha256(state.read_bytes()).hexdigest(), state.stat().st_mtime_ns)
        events = [json.loads(line)['event'] for line in log.read_text().splitlines() if line.strip()]
        unexpected = [event for event in events if event not in ('monitor_started', 'monitor_stopped')]
        if before != after or unexpected:
            raise RuntimeError('network/state changed during the sample; this was not an idle interval')
        cpu = usage.ru_utime + usage.ru_stime
        peak_kib = usage.ru_maxrss / 1024 if platform.system() == 'Darwin' else usage.ru_maxrss
        return {'label': label, 'version': subprocess.check_output([binary, '--version'], text=True).strip(),
                'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                'binary_bytes': Path(binary).stat().st_size, 'duration_seconds': round(elapsed, 3),
                'cpu_seconds': round(cpu, 6), 'cpu_percent_one_core': round(cpu / elapsed * 100, 4),
                'rss_median_mib': round(statistics.median(samples) / 1024, 3),
                'rss_max_sample_mib': round(max(samples) / 1024, 3),
                'peak_rss_including_startup_mib': round(peak_kib / 1024, 3),
                'state_writes': 0, 'action_executions': 0, 'steady_event_log_lines': 0,
                'poll_interval_seconds': interval, 'extra_local_sources_enabled': True,
                'network_bytes': 'not measured; request-count behavior is covered by tests'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='bin/netshift')
    parser.add_argument('--baseline')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--interval', type=int, default=30)
    parser.add_argument('--output')
    args = parser.parse_args()
    if not 30 <= args.seconds <= 600 or not 5 <= args.interval <= 60:
        parser.error('seconds must be 30..600 and interval 5..60')
    results = []
    if args.baseline:
        results.append(measure(args.baseline, 'baseline', args.seconds, args.interval))
    results.append(measure(args.binary, 'netshift', args.seconds, args.interval))
    report = {'platform': platform.system(), 'architecture': platform.machine(),
              'scope': 'single real watcher process, including startup; external CLI action costs excluded',
              'results': results}
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        with Path(args.output).open('x') as out:
            out.write(text)
    print(text, end='')


if __name__ == '__main__':
    main()
