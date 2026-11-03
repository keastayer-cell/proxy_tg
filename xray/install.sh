#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) -eq 0 ]]
source_dir=$(cd "$(dirname "$0")" && pwd)
mt_pid=$(systemctl show proxy-tg.service --value -p MainPID)
socks_pid=$(systemctl show proxy-socks.service --value -p MainPID)
install -d -m 0755 /opt/proxy_tg/xray
getent passwd proxy-xray >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin proxy-xray
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 - "$source_dir/release.json" "$work" <<'PY'
import hashlib,json,sys,urllib.request,zipfile
from pathlib import Path
release=json.loads(Path(sys.argv[1]).read_text());work=Path(sys.argv[2])
url=f'https://github.com/XTLS/Xray-core/releases/download/{release["version"]}/Xray-linux-64.zip'
with urllib.request.urlopen(url,timeout=60) as response:archive=response.read(64*1024*1024)
if hashlib.sha256(archive).hexdigest()!=release['sha256']:raise SystemExit('Official Xray checksum mismatch')
(work/'archive.zip').write_bytes(archive)
with zipfile.ZipFile(work/'archive.zip') as z:(work/'xray').write_bytes(z.read('xray'))
(work/'xray').chmod(0o755)
print('Pinned official Xray SHA256 verified')
PY
python3 "$source_dir/configure.py" "$work/xray"
"$work/xray" run -test -format json -config /etc/proxy_tg/xray/config.candidate.json >/dev/null
if [[ -f /etc/proxy_tg/xray/config.json ]]; then cp -p /etc/proxy_tg/xray/config.json /etc/proxy_tg/xray/config.json.previous; fi
if [[ -f /opt/proxy_tg/xray/xray ]]; then cp -p /opt/proxy_tg/xray/xray /opt/proxy_tg/xray/xray.previous; fi
install -m 0755 "$work/xray" /opt/proxy_tg/xray/xray.new
mv -f /opt/proxy_tg/xray/xray.new /opt/proxy_tg/xray/xray
install -m 0640 -o root -g proxy-xray /etc/proxy_tg/xray/config.candidate.json /etc/proxy_tg/xray/config.json
chown root:proxy-xray /etc/proxy_tg/xray
chmod 0750 /etc/proxy_tg/xray
install -m 0644 "$source_dir/proxy-xray.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable proxy-xray.service
if ! systemctl restart proxy-xray.service; then
  if [[ -f /etc/proxy_tg/xray/config.json.previous ]]; then
    cp -p /etc/proxy_tg/xray/config.json.previous /etc/proxy_tg/xray/config.json
    cp -p /opt/proxy_tg/xray/xray.previous /opt/proxy_tg/xray/xray
    systemctl restart proxy-xray.service
  fi
  exit 1
fi
sleep 2
systemctl is-active --quiet proxy-xray.service
test "$(systemctl show proxy-tg.service --value -p MainPID)" = "$mt_pid"
test "$(systemctl show proxy-socks.service --value -p MainPID)" = "$socks_pid"
echo 'Xray active on2053; MTProxy and SOCKS5 PIDs unchanged'
