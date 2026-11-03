import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import proxy


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.env = {'PROXY_HOST': '178.62.199.241', 'PROXY_SECRET': 'ab' * 16}

    def test_missing_and_invalid_secrets_are_rejected_without_disclosure(self):
        for secret in ('', 'short', 'dd' + 'ab' * 16, 'not-a-secret-token-DO-NOT-ECHO'):
            with self.subTest(secret_length=len(secret)):
                with self.assertRaises(ValueError) as result:
                    proxy.settings({**self.env, 'PROXY_SECRET': secret})
                if secret:
                    self.assertNotIn(secret, str(result.exception))

    def test_host_cannot_inject_query_or_shell_syntax(self):
        for host in ('', 'example.com/?secret=oops', 'host; touch /tmp/oops', 'https://example.com'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                proxy.settings({**self.env, 'PROXY_HOST': host})

    def test_ports_must_be_valid_and_separate(self):
        for config in ({'PROXY_PORT': '0'}, {'STATS_PORT': '80'}, {'PROXY_PORT': '8888'}, {'PROXY_PORT': '65536'}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                proxy.settings({**self.env, **config})

    def test_missing_telegram_config_blocks_start(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(ValueError):
            proxy.command({**self.env, 'PROXY_STATE_DIR': folder})

    def test_launch_bounds_resources_and_uses_requested_ports(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / 'config.current'
            config.mkdir()
            for name in proxy.UPSTREAM_URLS:
                (config / name).touch()
            argv = proxy.command({**self.env, 'PROXY_STATE_DIR': folder, 'PROXY_PORT': '8443'})
            for flag, value in [('-H', '8443'), ('-M', '1'), ('-C', '64'), ('--msg-buffers-size', '16777216')]:
                self.assertEqual(argv[argv.index(flag) + 1], value)

    def test_link_enables_padding_but_validation_never_prints_secret(self):
        with patch.dict(os.environ, self.env, clear=True):
            for action in ('validate', 'link'):
                output = io.StringIO()
                with patch('sys.argv', ['proxy.py', action]), contextlib.redirect_stdout(output):
                    self.assertEqual(proxy.main(), 0)
                if action == 'validate':
                    self.assertNotIn(self.env['PROXY_SECRET'], output.getvalue())
                else:
                    self.assertIn('secret=dd' + self.env['PROXY_SECRET'], output.getvalue())

    def test_init_cannot_overwrite_existing_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            args = ['proxy.py', 'init', '--host', self.env['PROXY_HOST'], '--output', str(path)]
            with patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(proxy.main(), 0)
            original = path.read_bytes()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch('sys.argv', args), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(proxy.main(), 1)
            self.assertEqual(path.read_bytes(), original)


class RefreshTests(unittest.TestCase):
    def test_failed_second_download_preserves_both_old_files(self):
        with tempfile.TemporaryDirectory() as folder:
            old = Path(folder) / 'config-old'
            old.mkdir()
            for name in proxy.UPSTREAM_URLS:
                (old / name).write_bytes(b'old')
            (Path(folder) / 'config.current').symlink_to(old.name)
            with patch.object(proxy, 'urlopen', side_effect=[io.BytesIO(b'new-secret'), TimeoutError()]):
                with self.assertRaises(TimeoutError):
                    proxy.refresh(folder)
            for name in proxy.UPSTREAM_URLS:
                self.assertEqual((Path(folder) / 'config.current' / name).read_bytes(), b'old')

    def test_complete_pair_switches_and_stays_private(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(proxy, 'urlopen', side_effect=[io.BytesIO(b'new-secret'), io.BytesIO(b'proxy_for 2 1.2.3.4:443;')]):
                proxy.refresh(folder)
            current = Path(folder) / 'config.current'
            self.assertTrue(current.is_symlink())
            self.assertEqual((current / 'proxy-secret').read_bytes(), b'new-secret')
            self.assertEqual((current / 'proxy-secret').stat().st_mode & 0o777, 0o600)

    def test_html_response_is_not_installed_as_telegram_config(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(proxy, 'urlopen', side_effect=[io.BytesIO(b'secret'), io.BytesIO(b'<html>Error</html>')]):
                with self.assertRaises(ValueError):
                    proxy.refresh(folder)
            self.assertFalse((Path(folder) / 'config.current').exists())


if __name__ == '__main__':
    unittest.main()
