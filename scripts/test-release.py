#!/usr/bin/env python3
"""Regression checks for public-file admission, archive metadata, and the formula bump."""
from pathlib import Path
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


public = module('public_check', HERE / 'check-public.py')
release = module('release_check', HERE / 'release.py')
bump = module('bump_formula', HERE / 'bump-formula.py')


class ReleaseChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'config').mkdir()
        (self.root / 'README.md').write_text('Public example')
        (self.root / 'release-files.txt').write_text('README.md\nrelease-files.txt\n')

    def test_private_profile_stays_out_and_leak_is_rejected(self):
        (self.root / 'config/private.local.json').write_text('{"resource_group":"private-canary-group"}')
        self.assertEqual(public.check(self.root), ['README.md', 'release-files.txt'])
        (self.root / 'README.md').write_text('private-canary-group')
        with self.assertRaisesRegex(ValueError, 'identifier from a private local profile') as caught:
            public.check(self.root)
        self.assertNotIn('private-canary-group', str(caught.exception))

    def test_findings_name_the_kind_never_the_value(self):
        token = 'ghp' + '_' + 'Q7' * 15  # Built at run time so this file stays clean.
        (self.root / 'README.md').write_text('token: ' + token)
        with self.assertRaisesRegex(ValueError, 'README.md: GitHub token') as caught:
            public.check(self.root)
        self.assertNotIn(token, str(caught.exception))
        (self.root / 'config/broken.local.json').write_text('{"nsg": "private-canary-nsg"')
        with self.assertRaisesRegex(ValueError, 'cannot parse private profile') as caught:
            public.check(self.root)
        self.assertNotIn('private-canary-nsg', str(caught.exception))

    def test_unexpected_public_ip_is_rejected(self):
        (self.root / 'README.md').write_text('Docs use 203.0.113.7, 10.0.0.1, 8.8.8.8, and 224.0.0.0/4.')
        self.assertEqual(public.check(self.root), ['README.md', 'release-files.txt'])
        real_looking = '.'.join(['151', '101', '1', '1'])  # Not a literal, so this file passes.
        (self.root / 'README.md').write_text(f'A pasted source list: 1.1.1.1/32, {real_looking}/32')
        with self.assertRaisesRegex(ValueError, 'public IPv4 outside documentation ranges') as caught:
            public.check(self.root)
        self.assertNotIn(real_looking, str(caught.exception))

    def test_private_identifier_match_ignores_case(self):
        (self.root / 'config/private.local.json').write_text('{"nsg":"Private-Canary-NSG"}')
        (self.root / 'README.md').write_text('private-canary-nsg')
        with self.assertRaisesRegex(ValueError, 'identifier from a private local profile'):
            public.check(self.root)

    def test_unlisted_file_private_path_and_traversal_are_rejected(self):
        (self.root / 'notes.txt').write_text('not reviewed')
        with self.assertRaisesRegex(ValueError, 'missing from release manifest'):
            public.check(self.root)
        for name in ['config/private.local.json', '../outside', '/absolute', '.local/backup',
                     'netshift', 'dist/x', '.env.production', '.vscode/settings.json']:
            (self.root / 'release-files.txt').write_text(name + '\n')
            with self.assertRaisesRegex(ValueError, 'unsafe/private'):
                public.manifest_files(self.root)

    def test_symlink_cannot_enter_archive(self):
        (self.root / 'alias').symlink_to('README.md')
        (self.root / 'release-files.txt').write_text('alias\n')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            public.manifest_files(self.root)

    def test_git_check_is_skipped_without_git_metadata(self):
        self.assertIsNone(public.git_files(self.root))

    def test_archive_is_deterministic_and_contains_no_machine_metadata(self):
        a, b = self.root / 'a.gz', self.root / 'b.gz'
        entries = [('netshift', b'executable', 0o755), ('LICENSE', b'license', 0o644)]
        release.archive(a, 'release', entries)
        release.archive(b, 'release', list(reversed(entries)))
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(a.read_bytes()), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), ['release/LICENSE', 'release/netshift'])
            for item in archive:
                self.assertEqual((item.uid, item.gid, item.mtime, item.uname, item.gname), (0, 0, 0, '', ''))
            self.assertEqual([item.mode for item in archive], [0o644, 0o755])

    def test_gzip_header_has_fixed_metadata(self):
        path = self.root / 'a.tar.gz'
        release.archive(path, 'release', [('LICENSE', b'license', 0o644)])
        header = path.read_bytes()[:10]
        self.assertEqual(header[:3], b'\x1f\x8b\x08')  # gzip magic, deflate
        self.assertEqual(header[3], 0)  # FLG: no file name, comment, or extra field
        self.assertEqual(int.from_bytes(header[4:8], 'little'), 0)  # MTIME
        self.assertEqual(header[8], 2)  # XFL: maximum compression (level 9)
        self.assertEqual(header[9], 255)  # OS: unknown, not the build host

    def test_archive_refuses_to_overwrite_and_odd_modes(self):
        path = self.root / 'a.tar.gz'
        path.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            release.archive(path, 'release', [('LICENSE', b'license', 0o644)])
        self.assertEqual(path.read_bytes(), b'existing')
        with self.assertRaisesRegex(ValueError, 'mode'):
            release.archive(self.root / 'b.tar.gz', 'release', [('LICENSE', b'license', 0o666)])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            release.archive(self.root / 'c.tar.gz', 'release', [('A', b'1', 0o644), ('A', b'2', 0o644)])

    def test_publish_refuses_overwrite_and_removes_partial_output(self):
        stage, out = self.root / 'stage', self.root / 'out'
        stage.mkdir()
        (stage / 'a').write_bytes(b'new a')
        (stage / 'b').write_bytes(b'new b')
        out.mkdir()
        (out / 'b').write_bytes(b'old b')
        with self.assertRaises(FileExistsError):
            release.publish(stage, out, ['a', 'b'])
        self.assertEqual(sorted(p.name for p in out.iterdir()), ['b'])
        self.assertEqual((out / 'b').read_bytes(), b'old b')
        fresh = self.root / 'fresh'
        with self.assertRaises(FileNotFoundError):
            release.publish(stage, fresh, ['a', 'missing'])
        self.assertFalse(fresh.exists())
        release.publish(stage, fresh, ['a', 'b'])
        self.assertEqual((fresh / 'a').read_bytes(), b'new a')


FORMULA = '''class Netshift < Formula
  desc "Run your own scripts when your public IP or connectivity changes"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "{base}/v{v}/netshift_{v}_darwin_arm64.tar.gz"
      sha256 "{darwin_arm64}"
    end
    on_intel do
      url "{base}/v{v}/netshift_{v}_darwin_amd64.tar.gz"
      sha256 "{darwin_amd64}"
    end
  end

  on_linux do
    on_arm do
      url "{base}/v{v}/netshift_{v}_linux_arm64.tar.gz"
      sha256 "{linux_arm64}"
    end
    on_intel do
      url "{base}/v{v}/netshift_{v}_linux_amd64.tar.gz"
      sha256 "{linux_amd64}"
    end
  end

  def install
    bin.install "netshift"
  end
end
'''
OLD = {target: digit * 64 for target, digit in zip(sorted(bump.TARGETS), '1234')}
NEW = {target: letter * 64 for target, letter in zip(sorted(bump.TARGETS), 'abcd')}


def formula_text(version, digests):
    return FORMULA.format(base=bump.RELEASES, v=version,
                          **{f'{goos}_{arch}': digest for (goos, arch), digest in digests.items()})


def sums_text(version, digests):
    lines = [f'{digest}  netshift_{version}_{goos}_{arch}.tar.gz' for (goos, arch), digest in digests.items()]
    lines += ['e' * 64 + '  BUILDINFO.json', 'f' * 64 + f'  netshift_{version}_source.tar.gz']
    return '\n'.join(sorted(lines)) + '\n'


class FormulaBumpChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.formula = self.root / 'netshift.rb'
        self.formula.write_text(formula_text('0.6.0', OLD))
        self.formula.chmod(0o640)
        self.sums = self.root / 'SHA256SUMS'
        self.sums.write_text(sums_text('0.7.0', NEW))

    def refuse(self, pattern, version='0.7.0', text=None):
        if text is not None:
            self.formula.write_text(text)
        before = self.formula.read_text()
        with self.assertRaisesRegex(ValueError, pattern):
            bump.bump(version, self.formula, self.sums)
        self.assertEqual(self.formula.read_text(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['SHA256SUMS', 'netshift.rb'])

    def test_targets_match_the_release_archives(self):
        self.assertEqual(sorted(bump.TARGETS), sorted(release.TARGETS))

    def test_bump_rewrites_only_urls_and_checksums(self):
        self.assertEqual(bump.bump('v0.7.0', self.formula, self.sums), ('0.6.0', True))
        self.assertEqual(self.formula.read_text(), formula_text('0.7.0', NEW))
        self.assertEqual(self.formula.stat().st_mode & 0o777, 0o640)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['SHA256SUMS', 'netshift.rb'])
        self.assertEqual(bump.bump('0.7.0', self.formula, self.sums), ('0.7.0', False))

    def test_sums_must_list_every_archive_once(self):
        lines = sums_text('0.7.0', NEW).splitlines()
        self.sums.write_text('\n'.join(line for line in lines if 'linux_amd64' not in line))
        self.refuse('no checksum for netshift_0.7.0_linux_amd64.tar.gz')
        self.sums.write_text('\n'.join(lines + lines[:1]))
        self.refuse('lists .* more than once')
        self.sums.write_text('\n'.join(lines + ['not a checksum line']))
        self.refuse('line 7 is not')
        self.sums.write_text('x' * (bump.SUMS_LIMIT + 1))
        self.refuse('larger than')

    def test_refuses_prerelease_and_downgrade(self):
        self.refuse('not a stable release version', version='0.7.0-rc.1')
        self.sums.write_text(sums_text('0.5.0', NEW))
        self.refuse('refusing to downgrade the formula from 0.6.0 to 0.5.0', version='0.5.0')

    def test_refuses_unexpected_formula_shapes(self):
        text = formula_text('0.6.0', OLD)
        darwin_arm = text.index('    on_arm do\n      url')
        darwin_intel = text.index('    on_intel do\n      url')
        swapped = text[:darwin_arm] + text[darwin_arm:darwin_intel].replace('on_arm', 'on_intel') \
            + text[darwin_intel:].replace('on_intel', 'on_arm', 1)
        cases = {
            'darwin/arm64 archive must be inside on_macos > on_arm': swapped,
            'explicitly': text.replace('  license', '  version "0.6.0"\n  license'),
            'exactly one release archive url': text.replace(
                '  def install', '  resource "extra" do\n    url "https://example.com/x.tar.gz"\n'
                '    sha256 "' + '0' * 64 + '"\n  end\n\n  def install'),
        }
        for pattern, case in cases.items():
            with self.subTest(pattern):
                self.refuse(pattern, text=case)
        without_linux = text[:text.index('  on_linux do')] + text[text.index('  def install'):]
        self.refuse('exactly one release archive url', text=without_linux)
        self.refuse('do not share one stable version', text=text.replace('/v0.6.0/', '/v0.5.0/', 1))

    def test_download_is_bounded_and_names_the_url(self):
        requests = []

        def opener(body=None, error=None):
            def open_url(request, timeout):
                requests.append((request.full_url, timeout))
                if error:
                    raise error
                return io.BytesIO(body)
            return open_url

        url = bump.RELEASES + '/v0.7.0/SHA256SUMS'
        self.assertEqual(bump.bump('0.7.0', self.formula, opener=opener(self.sums.read_bytes())),
                         ('0.6.0', True))
        self.assertEqual(requests, [(url, bump.DOWNLOAD_TIMEOUT)])
        with self.assertRaisesRegex(ValueError, 'larger than'):
            bump.bump('0.7.0', self.formula, opener=opener(b'x' * (bump.SUMS_LIMIT + 1)))
        missing = urllib.error.HTTPError(url, 404, 'Not Found', {}, None)
        with self.assertRaisesRegex(ValueError, 'cannot download .*/v0.8.0/SHA256SUMS: HTTP 404'):
            bump.bump('0.8.0', self.formula, opener=opener(error=missing))


@unittest.skipIf(shutil.which('git') is None, 'git is not installed')
class GitWorkTreeChecks(unittest.TestCase):
    """The git guard, run against a throwaway repository with the real .gitignore."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        shutil.copyfile(HERE.parent / '.gitignore', self.root / '.gitignore')
        (self.root / 'README.md').write_text('Public example')
        (self.root / 'release-files.txt').write_text('.gitignore\nREADME.md\nrelease-files.txt\n')
        self.expected = ['.gitignore', 'README.md', 'release-files.txt']
        self.git('init', '-q')

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        subprocess.run(['git', '-C', str(self.root), *args], env=env, check=True,
                       capture_output=True, timeout=30)

    def test_matching_work_tree_passes_untracked_and_tracked(self):
        (self.root / 'home.local.json').write_text('{"nsg": "private-canary-nsg"}')
        for name in ['notes.local.md', 'x.history.jsonl', '.env', '.envrc', 'netshift']:
            (self.root / name).write_text('private')
        for directory in ['.local', 'dist', 'bin', 'scripts/__pycache__']:
            (self.root / directory).mkdir(parents=True)
            (self.root / directory / 'x').write_text('private')
        self.assertEqual(public.check(self.root), self.expected)
        self.git('add', '-A')
        self.assertEqual(public.check(self.root), self.expected)

    def test_force_added_private_file_is_rejected(self):
        (self.root / 'config').mkdir()
        (self.root / 'config/home.local.json').write_text('{"nsg": "private-canary-nsg"}')
        self.assertEqual(public.check(self.root), self.expected)
        self.git('add', '-f', 'config/home.local.json')
        with self.assertRaisesRegex(ValueError, 'missing from the release manifest: config/home.local.json') as caught:
            public.check(self.root)
        self.assertNotIn('private-canary-nsg', str(caught.exception))

    def test_file_git_would_add_must_be_listed(self):
        # Without a .gitignore rule, git would publish a file that the
        # filesystem walk treats as private.
        (self.root / '.gitignore').write_text((self.root / '.gitignore').read_text().replace('.env*\n', ''))
        (self.root / '.env.production').write_text('private')
        with self.assertRaisesRegex(ValueError, 'missing from the release manifest: .env.production'):
            public.check(self.root)

    def test_gitignore_must_cover_every_canary(self):
        (self.root / '.gitignore').write_text('')
        with self.assertRaises(ValueError) as caught:
            public.check(self.root)
        message = str(caught.exception)
        self.assertIn('.gitignore does not ignore private/build canaries', message)
        for canary in ['config/x.local.json', 'x.local.md', '.local/x', 'dist/x', 'bin/x',
                       'netshift', 'x.history.jsonl', '.env']:
            self.assertIn(canary, message)

    def test_gitignore_must_not_hide_public_files(self):
        with (self.root / '.gitignore').open('a') as ignore:
            ignore.write('README.md\n.env.example\n')
        with self.assertRaises(ValueError) as caught:
            public.check(self.root)
        message = str(caught.exception)
        self.assertIn('release manifest lists files git ignores or cannot see: README.md', message)
        self.assertIn('.gitignore ignores public paths: .env.example, README.md', message)

    def test_root_binary_rule_is_anchored(self):
        (self.root / 'docs').mkdir()
        (self.root / 'docs/netshift').write_text('a public page')
        with self.assertRaisesRegex(ValueError, 'missing from release manifest: docs/netshift'):
            public.check(self.root)
        (self.root / 'release-files.txt').write_text('.gitignore\nREADME.md\ndocs/netshift\nrelease-files.txt\n')
        self.assertEqual(public.check(self.root), ['.gitignore', 'README.md', 'docs/netshift', 'release-files.txt'])


if __name__ == '__main__':
    unittest.main()
