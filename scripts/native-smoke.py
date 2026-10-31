#!/usr/bin/env python3
"""Real user-service lifecycle + offline hook; no cloud access or credentials.

The flow installs without --start (nothing may run, and doctor must warn
"installed, not started"), starts the service, checks that a second profile
file with the same profile name is refused without --replace, restarts it with
install --start, and then exercises status, logs, test-event, stop/start, and
uninstall. Everything uses a unique label; on macOS HOME is a temporary
directory. Cleanup is best effort and never hides the original error.

On Windows (see windows_smoke) the service is a Task Scheduler task and
%LOCALAPPDATA% is a temporary directory. The hook is a batch file, so its
argument passes through cmd.exe, and the flow also kills the watcher to check
that the task starts it again.

launchd keeps a persistent enabled/disabled override for every label that
`launchctl enable` or `disable` named, and launchctl has no verb that deletes
one. Cleanup re-enables this run's label, so the record it leaves says
"enabled", the default, instead of "disabled".
"""
from pathlib import Path
import argparse
import base64
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.dont_write_bytecode = True


def expect(condition, message):
    # Not `assert`: these checks must survive `python3 -O`.
    if not condition:
        raise RuntimeError(message)


def best_effort(description, step):
    """Run one cleanup step; report a failure without replacing the original error."""
    try:
        step()
    except Exception as exc:  # Cleanup must continue whatever went wrong.
        print(f'native smoke cleanup: {description}: {exc}', file=sys.stderr)


def manager_config_dir(environment_text):
    """The directory systemd --user searches: its XDG_CONFIG_HOME, else ~/.config.

    The shell's XDG_CONFIG_HOME does not matter; netshift follows the manager.
    """
    for line in environment_text.splitlines():
        if line.startswith('XDG_CONFIG_HOME='):
            value = line.split('=', 1)[1]
            if not value.startswith('/'):
                raise RuntimeError("the systemd user manager's XDG_CONFIG_HOME is not a plain absolute path")
            return Path(value)
    return Path.home() / '.config'


def wait_for(description, condition, seconds):
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() >= deadline:
            raise RuntimeError(description)
        time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default='bin/netshift')
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    system = platform.system()
    if system == 'Windows':
        windows_smoke(binary)
        return
    if system not in ('Darwin', 'Linux'):
        raise RuntimeError('native smoke supports macOS, Linux, and Windows')
    env = os.environ.copy()
    real_home = Path.home()
    profile = 'nsmoke-' + uuid.uuid4().hex[:12]
    owned_base = None
    unit = None
    attempted = False
    uninstalled = False
    with tempfile.TemporaryDirectory(prefix='netshift-native-') as tmp:
        root = Path(tmp)
        if system == 'Darwin':
            env['HOME'] = str(root / 'home')
            Path(env['HOME']).mkdir()
            owned_base = Path(env['HOME']) / 'Library/Application Support/NetShift'
            label = f'dev.netshift.{profile}'
            target = f'gui/{os.getuid()}/{label}'
            unit = Path(env['HOME']) / f'Library/LaunchAgents/{label}.plist'
        else:
            if not env.get('XDG_RUNTIME_DIR') and Path(f'/run/user/{os.getuid()}/bus').exists():
                env['XDG_RUNTIME_DIR'] = f'/run/user/{os.getuid()}'
            if env.get('XDG_RUNTIME_DIR'):
                env.setdefault('DBUS_SESSION_BUS_ADDRESS', 'unix:path=' + env['XDG_RUNTIME_DIR'] + '/bus')
            check = subprocess.run(['systemctl', '--user', 'show-environment'], env=env,
                                   capture_output=True, text=True, timeout=10)
            if check.returncode:
                raise RuntimeError('a running systemd user manager is required; use a disposable VM/user')
            config_dir = manager_config_dir(check.stdout)
            owned_base = config_dir / 'netshift'
            if owned_base.exists():
                raise RuntimeError('refusing to replace an existing Linux NetShift installation; use a disposable user')
            label = f'netshift-{profile}.service'
            unit = config_dir / f'systemd/user/{label}'
        receipt = root / 'hook-ran'
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        stopped = threading.Event()
        def refuse_tls():
            while not stopped.is_set():
                try:
                    conn, _ = listener.accept()
                    conn.close()
                except (TimeoutError, OSError):
                    continue
        thread = threading.Thread(target=refuse_tls, daemon=True)
        thread.start()
        profile_text = json.dumps({'version': 1, 'profile': profile,
            'monitor': {'interval_seconds': 5, 'timeout_seconds': 1,
                        'confirmations': 1, 'offline_confirmations': 1,
                        'ip_sources': [f'https://127.0.0.1:{port}/ip', f'https://localhost:{port}/ip']},
            'actions': {'offline_hook': {'type': 'command', 'on': ['connectivity_lost'],
                                         'timeout_seconds': 5,
                                         'command': ['/usr/bin/touch', str(receipt)]}}})
        config = root / 'smoke.json'
        config.write_text(profile_text)
        # The same profile name in another file: it shares the service.
        other = root / 'other' / 'smoke.json'
        other.parent.mkdir()
        other.write_text(profile_text)
        state = root / 'state.json'
        def netshift(profile_file, *args, check=True):
            result = subprocess.run([binary, '--config', str(profile_file), '--state', str(state), *args],
                                    env=env, capture_output=True, text=True, timeout=60)
            if check and result.returncode:
                raise RuntimeError(f'{" ".join(args)}: ' + (result.stderr or result.stdout))
            return result
        def run(*args, check=True):
            return netshift(config, *args, check=check)
        def tool(*args):
            subprocess.run(list(args), env=env, capture_output=True, check=False, timeout=15)
        def hook_saved():
            if not state.exists():
                return False
            saved = json.loads(state.read_text())
            return receipt.exists() and bool(saved.get('actions', {}).get('offline_hook', {}).get('last_success'))
        try:
            run('validate')
            attempted = True

            # Installed without --start, nothing runs and doctor warns.
            run('service', 'install')
            expect(unit.exists(), 'install did not write the service definition')
            expect(run('service', 'status', check=False).returncode != 0, 'install without --start loaded the service')
            time.sleep(3)  # a started watcher polls at once and writes state within a second
            expect(not state.exists() and not receipt.exists(), 'install without --start ran the watcher')
            # doctor exits 1 here (IP discovery is refused), so read its rows.
            rows = json.loads(run('doctor', '--json', check=False).stdout)
            service_rows = [r for r in rows if r['name'] == 'native service']
            expect(service_rows and service_rows[0]['status'] == 'WARN'
                   and service_rows[0]['detail'].startswith('installed, not started'),
                   f'doctor did not warn "installed, not started": {service_rows}')

            run('service', 'start')
            wait_for('native service did not execute the offline hook', hook_saved, 45)
            saved = json.loads(state.read_text())
            expect(saved['connectivity'] == 'offline', 'saved state is not offline')
            run('service', 'status')

            # Another profile file with the same profile name is refused.
            definition = unit.read_bytes()
            refused = netshift(other, 'service', 'install', '--start', check=False)
            expect(refused.returncode == 1 and '--replace' in refused.stderr,
                   'install from another profile file was not refused: ' + refused.stderr)
            refused = netshift(other, 'service', 'uninstall', '--apply', check=False)
            expect(refused.returncode == 1 and '--replace' in refused.stderr,
                   'uninstall from another profile file was not refused: ' + refused.stderr)
            expect(unit.read_bytes() == definition, 'a refused profile file changed the service definition')
            run('service', 'status')  # still running

            # An unchanged reinstall with --start restarts the job in place.
            run('service', 'install', '--start')
            expect(unit.read_bytes() == definition, 'an unchanged reinstall changed the definition')
            wait_for('service did not run after install --start',
                     lambda: run('service', 'status', check=False).returncode == 0, 15)

            expect('offline' in run('status').stdout, 'status does not report offline')
            expect(json.loads(run('status', '--json').stdout)['connectivity'] == 'offline',
                   'status --json does not report offline')
            expect('monitor_started' in run('logs', '--lines', '50', '--json').stdout,
                   'logs do not show monitor_started')
            before = state.read_bytes()
            run('test-event', 'connectivity_lost', '--ip', '8.8.8.8')
            expect(state.read_bytes() == before, 'test-event preview changed state')
            run('service', 'stop')
            expect(run('service', 'status', check=False).returncode != 0, 'stopped service still loaded')
            run('service', 'start')
            run('service', 'status')
            preview = run('service', 'uninstall').stdout
            expect(unit.exists(), 'uninstall preview removed the service definition')
            expect(f'Installed from: {config}' in preview, 'uninstall preview does not name the source profile')
            run('service', 'status')
            run('service', 'uninstall', '--apply')
            uninstalled = True
            expect(not unit.exists(), 'uninstall --apply left the service definition')
            expect((owned_base / 'profiles' / (profile + '.json')).exists(), 'uninstall removed the profile')
            expect((owned_base / 'bin/netshift').exists(), 'uninstall removed the shared binary')
            expect(state.exists(), 'uninstall removed state')
            expect(run('service', 'status', check=False).returncode != 0, 'uninstalled service still loaded')
            print(json.dumps({'platform': system, 'architecture': platform.machine(),
                              'native_service': 'PASS', 'install_without_start': 'PASS', 'offline_hook': 'PASS',
                              'replace_guard': 'PASS', 'stop_restart': 'PASS', 'status_logs_simulation': 'PASS',
                              'uninstall_preservation': 'PASS', 'azure_calls': 0}))
        finally:
            # Every step is best effort, so a cleanup failure never hides the
            # original error, and no loaded job is left pointing at a deleted
            # temporary HOME or binary.
            if attempted:
                if not uninstalled:
                    best_effort('service stop', lambda: run('service', 'stop', check=False))
                if system == 'Darwin':
                    best_effort('launchctl bootout', lambda: tool('launchctl', 'bootout', target))
                    best_effort('remove plist', lambda: unit.unlink(missing_ok=True))
                    # With the plist gone and the job booted out, enabling
                    # loads nothing; it only resets the persistent override.
                    best_effort('launchctl enable', lambda: tool('launchctl', 'enable', target))
                    # Logs are named after this run's unique profile, so removing
                    # them cannot touch other data, even in the real HOME.
                    for home in {Path(env['HOME']), real_home}:
                        for suffix in ('.log', '.log.1', '.stderr.log'):
                            log = home / 'Library/Logs/NetShift' / (profile + suffix)
                            best_effort('remove ' + log.name, lambda log=log: log.unlink(missing_ok=True))
                else:
                    best_effort('systemctl disable', lambda: tool(
                        'systemctl', '--user', 'disable', '--now', label))
                    wants = unit.parent / 'default.target.wants' / label
                    best_effort('remove wants link',
                                lambda: wants.unlink() if wants.is_symlink() else None)
                    best_effort('remove unit', lambda: unit.unlink(missing_ok=True))
                    best_effort('daemon-reload', lambda: tool('systemctl', '--user', 'daemon-reload'))
                    best_effort('reset-failed', lambda: tool('systemctl', '--user', 'reset-failed', label))
                    best_effort('remove installation', lambda: shutil.rmtree(owned_base)
                                if owned_base.exists() else None)
            stopped.set()
            listener.close()
            thread.join(timeout=1)


def refusing_listener():
    """A local endpoint that accepts and closes connections, so every IP source fails at once."""
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(0.2)
    stopped = threading.Event()

    def refuse():
        while not stopped.is_set():
            try:
                conn, _ = listener.accept()
                conn.close()
            except (TimeoutError, OSError):
                continue

    thread = threading.Thread(target=refuse, daemon=True)
    thread.start()

    def stop():
        stopped.set()
        listener.close()
        thread.join(timeout=1)
    return listener.getsockname()[1], stop


def console_text(raw):
    """schtasks output: UTF-16 for some queries, otherwise the console code page."""
    if raw.startswith(b'\xff\xfe') or (raw and raw.count(0) * 3 > len(raw)):
        return raw.decode('utf-16-le', errors='replace').lstrip('﻿')
    try:
        return raw.decode('oem', errors='replace')  # Python's name for the console code page
    except LookupError:
        return raw.decode('latin-1')


def windows_smoke(binary):
    env = os.environ.copy()
    profile = 'nsmoke-' + uuid.uuid4().hex[:12]
    task = '\\NetShift-' + profile
    attempted = uninstalled = False
    # Files a running watcher holds may outlive the run by a moment.
    with tempfile.TemporaryDirectory(prefix='netshift-native-', ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        env['LOCALAPPDATA'] = str(root / 'LocalAppData')
        Path(env['LOCALAPPDATA']).mkdir()
        owned_base = Path(env['LOCALAPPDATA']) / 'NetShift'
        definition_path = owned_base / 'tasks' / (profile + '.xml')
        installed_binary = owned_base / 'bin' / 'netshift.exe'
        log = owned_base / 'logs' / (profile + '.log')
        receipt = root / 'hook-ran'
        # The hook is a batch file; %1 arrives quoted, so cmd.exe prints the
        # argument's & ( ) ^ literally.
        hook = root / 'hook.cmd'
        hook.write_text('@echo off\r\n>"%~dp0hook-ran" echo %1\r\n')
        hook_argument = 'a&b (c) ^x'
        port, stop_listener = refusing_listener()
        profile_text = json.dumps({'version': 1, 'profile': profile,
            'monitor': {'interval_seconds': 5, 'timeout_seconds': 1,
                        'confirmations': 1, 'offline_confirmations': 1,
                        'ip_sources': [f'https://127.0.0.1:{port}/ip', f'https://localhost:{port}/ip']},
            'actions': {'offline_hook': {'type': 'command', 'on': ['connectivity_lost'],
                                         'timeout_seconds': 15,
                                         'command': [str(hook), hook_argument]}}})
        config = root / 'smoke.json'
        config.write_text(profile_text)
        other = root / 'other' / 'smoke.json'
        other.parent.mkdir()
        other.write_text(profile_text)
        state = root / 'state.json'

        def netshift(profile_file, *args, check=True):
            result = subprocess.run([binary, '--config', str(profile_file), '--state', str(state), *args],
                                    env=env, capture_output=True, encoding='utf-8', errors='replace', timeout=90)
            if check and result.returncode:
                raise RuntimeError(f'{" ".join(args)}: ' + (result.stderr or result.stdout))
            return result

        def run(*args, check=True):
            return netshift(config, *args, check=check)

        def schtasks(*args):
            result = subprocess.run(['schtasks.exe', *args], capture_output=True, timeout=30)
            return result.returncode, console_text(result.stdout + result.stderr)

        def task_xml():
            code, out = schtasks('/Query', '/TN', task, '/XML')
            return out if code == 0 else None

        def running():
            return run('service', 'status', check=False).returncode == 0

        def watcher_pids():
            # Only watchers of this run's installed profile, whose unique
            # name is in their command line. (Windows reports the long form
            # of a path that TEMP may give in its 8.3 short form.)
            script = ("Get-CimInstance Win32_Process -Filter \"Name='netshift.exe'\" | "
                      "Where-Object { $_.CommandLine -like ('*\\profiles\\' + $env:NSMOKE_PROFILE + '.json*') } | "
                      "ForEach-Object { $_.ProcessId }")
            encoded = base64.b64encode(script.encode('utf-16-le')).decode()  # no command-line quoting
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                    env=dict(env, NSMOKE_PROFILE=profile),
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError('cannot list watcher processes: ' + result.stderr)
            return [int(line) for line in result.stdout.split() if line.strip().isdigit()]

        def started_count():
            return log.read_text(encoding='utf-8', errors='replace').count('"monitor_started"') if log.exists() else 0

        def hook_saved():
            if not state.exists():
                return False
            saved = json.loads(state.read_text())
            return receipt.exists() and bool(saved.get('actions', {}).get('offline_hook', {}).get('last_success'))

        try:
            run('validate')
            attempted = True

            # Installed without --start, the task is registered disabled,
            # nothing runs, and doctor warns.
            run('service', 'install')
            expect(definition_path.exists(), 'install did not write the task definition')
            registered = task_xml()
            expect(registered is not None and '<Enabled>false</Enabled>' in registered,
                   'install without --start did not register a disabled task')
            expect(not running(), 'install without --start ran the watcher')
            time.sleep(3)  # a started watcher polls at once and writes state within a second
            expect(not state.exists() and not receipt.exists(), 'install without --start ran the watcher')
            rows = json.loads(run('doctor', '--json', check=False).stdout)
            service_rows = [r for r in rows if r['name'] == 'native service']
            expect(service_rows and service_rows[0]['status'] == 'WARN'
                   and service_rows[0]['detail'].startswith('installed, not started'),
                   f'doctor did not warn "installed, not started": {service_rows}')

            run('service', 'start')
            wait_for('the task did not execute the offline hook', hook_saved, 60)
            expect(receipt.read_text().strip() == f'"{hook_argument}"',
                   f'the batch hook received {receipt.read_text()!r}, not {hook_argument!r}')
            saved = json.loads(state.read_text())
            expect(saved['connectivity'] == 'offline', 'saved state is not offline')
            wait_for('service status does not report the running watcher', running, 30)
            rows = json.loads(run('doctor', '--json', check=False).stdout)
            expect([r for r in rows if r['name'] == 'native service'][0]['status'] == 'PASS',
                   f'doctor does not report the running task: {rows}')

            # Another profile file with the same profile name is refused.
            definition = definition_path.read_bytes()
            refused = netshift(other, 'service', 'install', '--start', check=False)
            expect(refused.returncode == 1 and '--replace' in refused.stderr,
                   'install from another profile file was not refused: ' + refused.stderr)
            refused = netshift(other, 'service', 'uninstall', '--apply', check=False)
            expect(refused.returncode == 1 and '--replace' in refused.stderr,
                   'uninstall from another profile file was not refused: ' + refused.stderr)
            expect(definition_path.read_bytes() == definition, 'a refused profile file changed the definition')
            expect(running(), 'a refused profile file stopped the watcher')

            # An unchanged reinstall with --start restarts the task, though
            # the watcher it stops holds the installed binary open.
            run('service', 'install', '--start')
            expect(definition_path.read_bytes() == definition, 'an unchanged reinstall changed the definition')
            wait_for('service did not run after install --start', running, 30)

            expect('offline' in run('status').stdout, 'status does not report offline')
            expect(json.loads(run('status', '--json').stdout)['connectivity'] == 'offline',
                   'status --json does not report offline')
            expect('monitor_started' in run('logs', '--lines', '50', '--json').stdout,
                   'logs do not show monitor_started')
            before = state.read_bytes()
            run('test-event', 'connectivity_lost', '--ip', '8.8.8.8')
            expect(state.read_bytes() == before, 'test-event preview changed state')

            # A watcher that dies is started again by the task's trigger.
            wait_for('no watcher process found', watcher_pids, 30)
            starts = started_count()
            for pid in watcher_pids():
                subprocess.run(['taskkill.exe', '/F', '/PID', str(pid)], capture_output=True, timeout=30)
            wait_for('the killed watcher is still reported running', lambda: not running(), 30)
            wait_for('the task did not start the watcher again', lambda: running() and started_count() > starts, 150)

            run('service', 'stop')
            expect(not running(), 'stopped service still runs')
            expect('<Enabled>false</Enabled>' in (task_xml() or ''), 'stop left the task enabled')
            wait_for('a watcher process outlived stop', lambda: not watcher_pids(), 30)
            run('service', 'start')
            wait_for('service did not run after start', running, 30)
            preview = run('service', 'uninstall').stdout
            expect(definition_path.exists(), 'uninstall preview removed the definition')
            expect(f'Installed from: {config}' in preview, 'uninstall preview does not name the source profile')
            expect(running(), 'uninstall preview stopped the watcher')
            run('service', 'uninstall', '--apply')
            uninstalled = True
            expect(not definition_path.exists(), 'uninstall --apply left the definition')
            expect(task_xml() is None, 'uninstall --apply left the task registered')
            expect((owned_base / 'profiles' / (profile + '.json')).exists(), 'uninstall removed the profile')
            expect(installed_binary.exists(), 'uninstall removed the shared binary')
            expect(state.exists() and log.exists(), 'uninstall removed state or the event log')
            expect(not running(), 'uninstalled service still runs')
            wait_for('a watcher process outlived uninstall', lambda: not watcher_pids(), 30)
            print(json.dumps({'platform': 'Windows', 'architecture': platform.machine(),
                              'native_service': 'PASS', 'install_without_start': 'PASS', 'offline_hook': 'PASS',
                              'batch_hook_arguments': 'PASS', 'replace_guard': 'PASS', 'restart_after_kill': 'PASS',
                              'stop_restart': 'PASS', 'status_logs_simulation': 'PASS',
                              'uninstall_preservation': 'PASS', 'azure_calls': 0}))
        except Exception:
            # What Task Scheduler and the watcher said, for the CI log.
            for description, show in [
                ('task', lambda: schtasks('/Query', '/TN', task, '/V', '/FO', 'LIST')[1]),
                ('task CSV', lambda: schtasks('/Query', '/TN', task, '/V', '/FO', 'CSV', '/NH')[1]),
                ('service status', lambda: (lambda r: r.stdout + r.stderr)(run('service', 'status', check=False))),
                ('event log', lambda: log.read_text(encoding='utf-8', errors='replace')[-6000:] if log.exists() else 'none'),
            ]:
                best_effort(description, lambda show=show, description=description: print(
                    f'--- {description}\n{show()}', file=sys.stderr))
            raise
        finally:
            if attempted:
                if not uninstalled:
                    best_effort('service stop', lambda: run('service', 'stop', check=False))
                best_effort('schtasks /End', lambda: schtasks('/End', '/TN', task))
                best_effort('schtasks /Delete', lambda: schtasks('/Delete', '/TN', task, '/F'))
                best_effort('kill watchers', lambda: [subprocess.run(['taskkill.exe', '/F', '/PID', str(pid)],
                                                                     capture_output=True, timeout=30)
                                                      for pid in watcher_pids()])
            stop_listener()


if __name__ == '__main__':
    main()
