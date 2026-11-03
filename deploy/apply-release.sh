#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) -eq 0 ]]
revision=${1:?Provide Git commit SHA}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
base=/opt/proxy_tg
incoming=$base/incoming
# The marker is created only for an explicitly approved first activation.
if [[ ! -f "$base/.allow-deploy-start" ]] && systemctl is-active --quiet proxy-tg.service; then
  echo 'Refusing to change a running proxy without the activation marker'
  exit 1
fi
deployment=${2:-manual-$(date -u +%Y%m%d%H%M%S)}
[[ "$deployment" =~ ^[A-Za-z0-9-]+$ ]]
release=$base/releases/$revision-$deployment
test ! -e "$release"
install -d -m 0755 "$release/bin" "$release/deploy"
install -m 0755 "$incoming/dist/bin/mtproto-proxy" "$release/bin/mtproto-proxy"
install -m 0644 "$incoming/proxy.py" "$release/proxy.py"
install -m 0644 "$incoming/dist/UPSTREAM_REVISION" "$release/UPSTREAM_REVISION"
install -m 0644 "$incoming/deploy/"*.service "$incoming/deploy/"*.timer "$release/deploy/"
python3 -m py_compile "$release/proxy.py"
previous=$(readlink -f "$base/current" || true)
ln -s "$release" "$base/.current-$revision"
mv -Tf "$base/.current-$revision" "$base/current"
install -m 0644 "$release/deploy/"*.service "$release/deploy/"*.timer /etc/systemd/system/
systemctl daemon-reload
if [[ ! -f "$base/.allow-deploy-start" ]]; then
  echo 'Release prepared; proxy remains stopped (activation marker absent)'
  exit 0
fi
systemctl enable proxy-tg.service proxy-tg-refresh.timer
systemctl start proxy-tg-refresh.timer
if systemctl restart proxy-tg.service; then
for attempt in $(seq 1 20); do
  if systemctl is-active --quiet proxy-tg.service && curl -fsS --max-time 2 "http://127.0.0.1:$(sed -n 's/^STATS_PORT=//p' /etc/proxy_tg/proxy.env)/stats" >/dev/null; then
    sleep 3
    systemctl is-active --quiet proxy-tg.service && exit 0
  fi
  sleep 1
done
fi
# Restore the previous known release on failed activation. No secrets are logged.
if [[ -n "$previous" && "$previous" != "$release" ]]; then
  ln -s "$previous" "$base/.rollback-$revision"
  mv -Tf "$base/.rollback-$revision" "$base/current"
  install -m 0644 "$previous/deploy/"*.service "$previous/deploy/"*.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl restart proxy-tg.service
else
  systemctl stop proxy-tg.service
fi
echo 'Proxy health check failed; previous release restored if available'
exit 1
