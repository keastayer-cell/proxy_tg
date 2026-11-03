"""Configuration and lifecycle for the official Telegram MTProxy (Python stdlib)."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
from urllib.parse import urlencode
from urllib.request import urlopen

UPSTREAM_URLS = {
    'proxy-secret': 'https://core.telegram.org/getProxySecret',
    'proxy-multi.conf': 'https://core.telegram.org/getProxyConfig',
}


def load_env(path):
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
            raise ValueError('Invalid environment file')
        os.environ[key] = value.strip()


def settings(env):
    host = env.get('PROXY_HOST', '').strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('PROXY_HOST must be an IP address or hostname')
    secret = env.get('PROXY_SECRET', '')
    if not re.fullmatch(r'[0-9a-fA-F]{32}', secret):
        raise ValueError('PROXY_SECRET must contain 32 hexadecimal characters')
    port = int(env.get('PROXY_PORT', '443'))
    stats = int(env.get('STATS_PORT', '8888'))
    if not 1 <= port <= 65535 or not 1024 <= stats <= 65535 or port == stats:
        raise ValueError('Invalid or conflicting ports')
    return host, port, stats, secret.lower()


def tls_domain(env):
    domain = env.get('PROXY_TLS_DOMAIN', '').strip().lower()
    if domain and not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain):
        raise ValueError('Invalid PROXY_TLS_DOMAIN')
    return domain


def command(env):
    _, port, stats, secret = settings(env)
    config = Path(env.get('PROXY_STATE_DIR', '/var/lib/proxy_tg')) / 'config.current'
    if not all((config / name).is_file() for name in UPSTREAM_URLS):
        raise ValueError('Telegram configuration missing; run refresh first')
    domain = tls_domain(env)
    return [
        env.get('PROXY_BINARY', '/opt/proxy_tg/current/bin/mtproto-proxy'),
        '-p', str(stats), '-H', str(port), '-S', secret,
        '-M', '0' if domain else '1', '-C', '64', '-c', '512',
        '--cpu-threads', '1', '--io-threads', '1',
        '--msg-buffers-size', '16777216',
        *(['-D', domain] if domain else []),
        '--aes-pwd', str(config / 'proxy-secret'), str(config / 'proxy-multi.conf'),
    ]


def refresh(state_dir):
    """Switch a complete downloaded pair atomically; retain the last good pair."""
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    payloads = {}
    for name, url in UPSTREAM_URLS.items():
        with urlopen(url, timeout=20) as response:
            payload = response.read(1024 * 1024 + 1)
        if not payload or len(payload) > 1024 * 1024:
            raise ValueError('Invalid Telegram configuration size')
        if name.endswith('.conf') and b'proxy_for' not in payload:
            raise ValueError('Invalid Telegram proxy configuration')
        payloads[name] = payload
    generation = state / ('config-' + secrets.token_hex(8))
    generation.mkdir(mode=0o700)
    temporary_link = state / ('.config-' + secrets.token_hex(8))
    try:
        for name, payload in payloads.items():
            path = generation / name
            path.write_bytes(payload)
            path.chmod(0o600)
        temporary_link.symlink_to(generation.name)
        os.replace(temporary_link, state / 'config.current')
    except BaseException:
        temporary_link.unlink(missing_ok=True)
        shutil.rmtree(generation)
        raise
    # Keep one previous generation for recovery, plus the current generation.
    previous = sorted((p for p in state.glob('config-*') if p.is_dir() and p != generation),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    for old in previous[1:]:
        shutil.rmtree(old)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file')
    parser.add_argument('action', choices=['init', 'validate', 'run', 'refresh', 'link', 'health'])
    parser.add_argument('--host')
    parser.add_argument('--output', default='/etc/proxy_tg/proxy.env')
    args = parser.parse_args()
    try:
        if args.env_file:
            load_env(args.env_file)
        if args.action == 'init':
            env = {'PROXY_HOST': args.host or '', 'PROXY_SECRET': secrets.token_hex(16)}
            settings(env)
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write('\n'.join(f'{key}={value}' for key, value in env.items()) + '\nPROXY_PORT=443\nSTATS_PORT=8888\n')
            print('Private configuration created')
        elif args.action == 'refresh':
            refresh(os.environ.get('PROXY_STATE_DIR', '/var/lib/proxy_tg'))
            print('Telegram configuration refreshed')
        elif args.action == 'health':
            _, port, _, _ = settings(os.environ)
            with socket.create_connection(('127.0.0.1', port), timeout=2):
                pass
            print('OK: local proxy TCP listener')
        elif args.action == 'run':
            argv = command(os.environ)
            os.execv(argv[0], argv)
        else:
            host, port, _, secret = settings(os.environ)
            domain = tls_domain(os.environ)
            if args.action == 'link':
                client_secret = 'ee' + secret + domain.encode('ascii').hex() if domain else 'dd' + secret
                print('https://t.me/proxy?' + urlencode({'server': host, 'port': port, 'secret': client_secret}))
            else:
                print('Configuration valid (secret hidden)')
    except (OSError, ValueError) as error:
        # Do not echo configuration, command line, response content or secrets.
        print(f'Proxy operation failed: {type(error).__name__}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
