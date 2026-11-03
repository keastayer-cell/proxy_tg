#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
revision=$(tr -d '\n' < UPSTREAM_REVISION)
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$work" init -q
git -C "$work" fetch -q --depth 1 https://github.com/TelegramMessenger/MTProxy.git "$revision"
git -C "$work" checkout -q --detach FETCH_HEAD
test "$(git -C "$work" rev-parse HEAD)" = "$revision"
make -C "$work" -j1
install -d dist/bin
install -m 0755 "$work/objs/bin/mtproto-proxy" dist/bin/mtproto-proxy
cp UPSTREAM_REVISION dist/UPSTREAM_REVISION
