#!/usr/bin/env bash
# Run as root on the destination VPS. Does not start the proxy.
set -euo pipefail
[[ $(id -u) -eq 0 ]]
config_host=${1:?Provide the public VPS IP or hostname}
base=/opt/proxy_tg
getent passwd proxy-tg >/dev/null || useradd --system --home-dir /var/lib/proxy_tg --shell /usr/sbin/nologin proxy-tg
install -d -m 0755 "$base/releases" /etc/proxy_tg
install -d -m 0700 -o proxy-tg -g proxy-tg /var/lib/proxy_tg
if [[ ! -f /etc/proxy_tg/proxy.env ]]; then
  python3 "$base/incoming/proxy.py" init --host "$config_host"
fi
python3 "$base/incoming/proxy.py" --env-file /etc/proxy_tg/proxy.env validate
if [[ ! -e /var/lib/proxy_tg/config.current ]]; then
  runuser -u proxy-tg -- python3 "$base/incoming/proxy.py" refresh
fi
