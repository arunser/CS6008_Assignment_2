# Phase 7: DNS-over-TLS and the last mile

This builds on Phase 6. There the stub client was fooled because the resolver-to-
client hop is plain cleartext DNS, which anyone on the path can forge. Phase 7 closes
that gap: the client talks to the resolver over TLS (DoT, port 853) and validates the
resolver's certificate against a private CA. A forger on the wire can no longer read
or rewrite the last hop, and a server that can't prove it's the resolver is rejected.

The new pieces, all scaffolded onto the Phase 3 signed hierarchy:
- a private CA (OpenSSL) that issues the resolver a cert with SAN resolver.cs6008.local,
- the resolver listening on port 853 with TLS alongside its cleartext port 53,
- a rogue DoT server holding a cert for the same name but signed by nobody trusted,
- toggles on the attacker and edge-router to try three different attacks.

The client queries with kdig over TLS, pinning our CA and the hostname. Two shells
make the contrast: `strict` (DoT only) and `opp` (DoT, else fall back to cleartext).

## Build and run

Scaffolded from Phase 6, with the pki CA, the rogue DoT server, and the resolver's
TLS listener added. Deploy is the standard signed hierarchy plus the CA.

```
docker compose up -d --build
sleep 15
docker compose up -d
docker compose ps --format '{{.Name}} {{.Status}}' | grep resolver   # must be Up
```

Define the two client shells (used below):

```
DOT='kdig +tls +tls-ca=/pki/ca.pem +tls-hostname=resolver.cs6008.local @resolver.cs6008.local example.com +short'
alias strict="docker compose exec client sh -c \"$DOT\""
alias opp="docker compose exec client sh -c \"$DOT 2>/dev/null | grep -q . && $DOT || dig +short @172.16.2.10 example.com\""
```

## Verify over DoT

Resolve by name over TLS, validating the cert against our CA, and confirm nothing
leaks in cleartext.

```
docker compose exec client kdig +tls +tls-ca=/pki/ca.pem +tls-hostname=resolver.cs6008.local @resolver.cs6008.local example.com
docker compose exec -d edge-router sh -c 'tcpdump -ni any -w /tmp/ct.pcap "udp port 53 and host 172.16.1.10"'
docker compose exec client kdig +tls +tls-ca=/pki/ca.pem +tls-hostname=resolver.cs6008.local @resolver.cs6008.local example.com >/dev/null
docker compose exec edge-router sh -c 'tcpdump -nr /tmp/ct.pcap | wc -l'   # 0
```

A TLS1.3 session, example.com = 172.16.1.20 with the ad flag, and 0 cleartext packets
for that lookup. The last mile is now encrypted and authenticated.

## Attack 1 — forge the cleartext, DoT is untouched

```
FORGE=1 docker compose up -d attacker; sleep 3
strict   
opp     
```

The attacker forges the cleartext hop as in Phase 6, but the client is on DoT, so the
forgery never reaches it. Both shells stay on the real answer.

## Attack 2 — block 853 and force a downgrade

```
BLOCK853=1 FORGE=1 docker compose up -d attacker; sleep 3
strict   
opp      
```

Dropping port 853 kills DoT. A strict client fails closed and gets nothing. An
opportunistic client falls back to cleartext, where the forge is waiting, and lands on
the rogue page. This is the real weakness of opportunistic DoT.

## Attack 3 — rogue DoT server, defeated by the cert check

```
docker compose down
ROGUE_MITM=1 FORGE=1 docker compose up -d --build; sleep 12
strict   
opp      
```

The edge-router now DNATs the client's 853 traffic to the rogue DoT server. The rogue
holds a cert for resolver.cs6008.local, but it isn't signed by our CA, so the client's
certificate check fails and the handshake is refused. A strict client is safe. An
opportunistic client still falls back to cleartext and gets forged. The CA is what
stops the impersonation, exactly as a public CA would on the real internet.

## Capturing evidence

The screenshots in evidence/ cover DoT working with no cleartext, DoT resisting the
forge, the block-853 downgrade, the rogue-MITM deploy, and the rogue cert being
rejected.

```
# 01 DoT works + 0 cleartext:  the kdig TLS block and the tcpdump wc -l
# 02 FORGE=1:                   strict/opp -> 172.16.1.20
# 03 BLOCK853=1 FORGE=1:        strict timeout, opp -> 172.16.1.30
# 04 ROGUE_MITM=1 up --build:   the deploy (iptables in the tools image)
# 05 rogue cert rejected:       strict -> handshake failed, opp -> 172.16.1.30
```
