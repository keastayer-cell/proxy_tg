#!/usr/bin/env bash
set -euo pipefail
: "${VPS_HOST:?}" "${VPS_USER:?}" "${DEPLOY_KEY:?}" "${VPS_FINGERPRINT:?}"
: "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
[[ "$VPS_HOST" =~ ^[A-Za-z0-9.-]+$ ]]
[[ "$VPS_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+-[0-9]+$ ]]
known_hosts=$(pwd)/deploy/known_hosts
actual_fingerprint=$(ssh-keygen -lf "$known_hosts" -E sha256 | awk '{print $2}')
[[ "$actual_fingerprint" = "$VPS_FINGERPRINT" ]]
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 0700 "$work"
printf '%s\n' "$DEPLOY_KEY" > "$work/key"
chmod 0600 "$work/key"
unset DEPLOY_KEY
ssh-keygen -y -f "$work/key" >/dev/null
options=(-i "$work/key" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=20
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known_hosts" -o HostKeyAlgorithms=ssh-ed25519)
tar -czf "$work/release.tgz" socks
ssh "${options[@]}" "$VPS_USER@$VPS_HOST" 'install -d -m 0755 /opt/proxy_tg/socks-source; tar -xzf - --strip-components=1 -C /opt/proxy_tg/socks-source' < "$work/release.tgz"
ssh "${options[@]}" "$VPS_USER@$VPS_HOST" "bash /opt/proxy_tg/socks-source/install.sh"
