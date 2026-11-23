#!/bin/sh
set -eu
# Stop only AWG; its baseline no-transit guard remains while forwarding is enabled.
systemctl disable --now awg31.service
rm -f /etc/systemd/system/awg31.service /etc/sysctl.d/90-awg31-forward.conf
systemctl daemon-reload
if [ "${1:-}" = --restore-forwarding ]; then
    # Operator must first confirm no later service depends on IPv4 forwarding.
    sysctl -w net.ipv4.ip_forward=0
    iptables -w -C FORWARD -m comment --comment awg31-baseline-no-other-transit -j DROP && iptables -w -D FORWARD -m comment --comment awg31-baseline-no-other-transit -j DROP
fi
echo 'AWG31 stopped; guest profile revoked. Existing proxy services were not restarted.'
echo 'Default: keep forwarding guard. Use --restore-forwarding only after checking later dependencies.'
echo 'Audit material and disabled keys remain in protected /opt/awg31; Docker is untouched.'
