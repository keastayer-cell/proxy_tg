"""Generate Telegram-only authenticated Dante configuration, without credentials."""
import ipaddress
from pathlib import Path

NETWORKS = (
    '91.108.56.0/22', '91.108.4.0/22', '91.108.8.0/22',
    '91.108.16.0/22', '91.108.12.0/22', '149.154.160.0/20',
    '91.105.192.0/23', '91.108.20.0/22', '185.76.151.0/24',
)


def render(port=8443, username='tgproxy'):
    if not 1024 <= port <= 65535 or port == 443:
        raise ValueError('SOCKS listener must be separate from MTProxy')
    if username != 'tgproxy':
        raise ValueError('Unexpected proxy user')
    text = f'''logoutput: stderr
internal: 0.0.0.0 port = {port}
external: eth0
user.privileged: root
user.notprivileged: nobody
clientmethod: none
socksmethod: username
timeout.negotiate: 20
timeout.connect: 10
client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
}}
'''
    for network in NETWORKS:
        ipaddress.ip_network(network)
        text += f'''socks pass {{
    from: 0.0.0.0/0 to: {network}
    command: connect
    protocol: tcp
    proxyprotocol: socks_v5
    socksmethod: username
    user: {username}
}}
'''
    return text + '''socks block {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}
'''


if __name__ == '__main__':
    import sys
    Path(sys.argv[1]).write_text(render())
