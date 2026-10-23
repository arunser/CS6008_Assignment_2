# Phase 6: End-to-end, the last mile

This builds on Phase 3's signed hierarchy. The resolver validates every answer, so
the forgeries from Phases 2 and 4 die there. But validation at the resolver only
protects the resolver. The hop from the resolver to the client is still plain,
unsigned DNS, and a stub client takes whatever arrives on it. So here the attacker
moves onto the client subnet and forges that last hop.

The attacker is the same interceptor with two constants changed: it now sits at
172.16.1.100 on the client subnet, and the host it relays to is the client at
172.16.1.10. The edge-router diverts the client's inbound replies through it. The
forge logic is unchanged, example.com's A is rewritten to the rogue server.

Two clients make the point, both from the one client container: a plain stub that
asks the resolver and trusts the answer, and a locally-validating client (delv) that
revalidates the chain itself against the root anchor.

## Build and run

Scaffolded from Phase 3, with the interceptor's constants moved to the client subnet
and the diversion route moved to the edge-router. Deploy is the standard signed
hierarchy, forging off.

```
docker compose up -d --build
sleep 15
docker compose up -d
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"
```

## Verify transparent (before the attack)

With forging off, example.com resolves normally and curl gets the real page.

```
docker compose exec client dig +short @172.16.2.10 example.com      
docker compose exec client curl -s http://example.com              
```

## Attack both clients

Turn forging on, flush, then ask as each client.

```
FORGE=1 docker compose up -d attacker
sleep 3
docker compose restart resolver; sleep 4
# Client A — plain stub
docker compose exec client dig +short @172.16.2.10 example.com      
docker compose exec client curl -s http://example.com              
# Client B — locally validating
docker compose exec client delv -a /signed/root-anchor.conf @172.16.2.10 example.com
```

Client A gets 172.16.1.30 and lands on the rogue page. Client B refuses: delv
revalidates the chain against the root anchor, finds the forged A has no matching
signature, and reports `RRSIG failed to verify` / `resolution failed`. The attacker
forged the resolver-to-client A record, which the stub has no way to check, but the
validating client checks it anyway and catches the forgery.

## Capturing evidence

The screenshots in evidence/ show the transparent baseline with the real page, Client
A being fooled onto the rogue page, and Client B refusing the same forged answer.

```
docker compose exec client dig +short @172.16.2.10 example.com
docker compose exec client curl -s http://example.com                                 # 01 baseline
FORGE=1 docker compose up -d attacker; sleep 3; docker compose restart resolver; sleep 4
docker compose exec client dig +short @172.16.2.10 example.com
docker compose exec client curl -s http://example.com                                 # 02 Client A
docker compose exec client delv -a /signed/root-anchor.conf @172.16.2.10 example.com  # 03 Client B
```
