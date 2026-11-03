#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) -eq 0 ]]
source_dir=$(cd "$(dirname "$0")" && pwd)
mtproxy_pid_before=$(systemctl show proxy-tg.service --value -p MainPID)
if ! command -v danted >/dev/null; then
  systemctl mask danted.service
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends dante-server
fi
install -d -m 0755 /opt/proxy_tg/socks /etc/proxy_tg
getent passwd tgproxy >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin tgproxy
python3 - <<'PY'
import json,os,secrets,subprocess
from pathlib import Path
p=Path('/etc/proxy_tg/socks-credentials.json')
if not p.exists():
    credentials={'host':'178.62.199.241','port':8443,'username':'tgproxy','password':secrets.token_urlsafe(24)}
    subprocess.run(['chpasswd'],input=credentials['username']+':'+credentials['password']+'\n',text=True,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as handle:json.dump(credentials,handle)
print('Proxy credentials ready (password hidden)')
PY
python3 "$source_dir/configure.py" /etc/proxy_tg/socks.conf.candidate
/usr/sbin/danted -V -f /etc/proxy_tg/socks.conf.candidate
if [[ -f /etc/proxy_tg/socks.conf ]]; then cp -p /etc/proxy_tg/socks.conf /etc/proxy_tg/socks.conf.previous; fi
install -m 0644 "$source_dir/mss.sh" /opt/proxy_tg/socks/mss.sh
install -m 0644 /etc/proxy_tg/socks.conf.candidate /etc/proxy_tg/socks.conf
install -m 0644 "$source_dir/"*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable proxy-socks.service
systemctl restart proxy-socks-mss.service
if ! systemctl restart proxy-socks.service; then
  if [[ -f /etc/proxy_tg/socks.conf.previous ]]; then
    cp -p /etc/proxy_tg/socks.conf.previous /etc/proxy_tg/socks.conf
    systemctl restart proxy-socks.service
  fi
  exit 1
fi
sleep 2
systemctl is-active --quiet proxy-socks.service
bash /opt/proxy_tg/socks/mss.sh check
test "$(systemctl show proxy-tg.service --value -p MainPID)" = "$mtproxy_pid_before"
echo 'SOCKS5 running; MTProxy PID unchanged' 
