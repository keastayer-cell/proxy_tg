#!/usr/bin/env bash
set -euo pipefail
rule=(-p tcp --sport 8443 --tcp-flags SYN,RST SYN -m comment --comment proxy-tg-socks-mss -j TCPMSS --set-mss 1024)
case ${1:?} in
  apply)
    iptables -t mangle -C OUTPUT "${rule[@]}" 2>/dev/null || iptables -t mangle -I OUTPUT 1 "${rule[@]}"
    ;;
  remove)
    while iptables -t mangle -C OUTPUT "${rule[@]}" 2>/dev/null; do
      iptables -t mangle -D OUTPUT "${rule[@]}"
    done
    ;;
  check) iptables -t mangle -C OUTPUT "${rule[@]}" ;;
  *) exit 2 ;;
esac
