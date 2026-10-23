# Phase 3: Defending with DNSSEC

This builds on Phase 2. The hierarchy, the subnets, and the on-path attacker are
all exactly the same. I didn't touch the attacker at all, it still runs the same
C/libpcap interceptor and still forges example.com. What changes is the data it's
tampering with: every zone is now DNSSEC-signed, and the resolver validates the
chain before it answers the client. So the forged A record still arrives, but it
no longer matches the signature, and the resolver refuses to hand it over.

The signing is done per-server. Each authoritative server signs its own zone and
publishes its DS to its parent. example.com (domain-ns) signs its zone and hands
its DS up to com. com (tld-ns) signs its zone including that DS and hands its DS up
to root. Root (root-ns) signs last, and writes out the trust anchor the resolver
pins.

Each server generates its own KSK and ZSK at deploy (ECDSAP256SHA256, algorithm 13)
into a shared signed volume, so no private key is ever committed. The resolver runs
`dnssec-validation yes` with the root's public key as a static trust anchor. The
client can also validate for itself with `delv` against the same anchor.

Tooling is unchanged from Phase 1 and 2: Docker + Compose, dig/delv/curl.

## Build and run

From this directory. The signing chain is bottom-up, so root-ns signs last. Give it
a few seconds before checking.

```
docker compose up -d --build
sleep 15                                      
docker compose up -d                          # run once more if any container shows "Created"
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"
```

You should get three lines, one per zone, each saying `signed by itself; DS/anchor
published`. If only two show up, root-ns hasn't finished, so wait and re-run the grep.

## Verify the signed hierarchy

With forging off (`FORGE` defaults to 0, so the attacker just relays transparently),
check the answer is authenticated and the whole chain validates against our root key.

```
docker compose exec client dig +dnssec @172.16.2.10 example.com
docker compose exec client delv -a /signed/root-anchor.conf @172.16.2.10 example.com
```

dig comes back `status: NOERROR` with `flags: qr rd ra ad`. The ad (authenticated
data) bit is the point, and there's an RRSIG next to the A record. delv prints
`; fully validated`. That's the resolver and the client both confirming the chain
from the root anchor down to example.com's key.

If you get SERVFAIL here, the chain or the relay wasn't ready when the resolver
first primed and it cached a failure. A clean redeploy fixes it: `docker compose
down -v && docker compose up -d --build`, wait about 15s for the three "signed by
itself" lines, then verify. Don't restart the resolver before this check.

## Re-run the attack

Exactly as Phase 2. Turn forging on, flush the resolver's cache, look it up. This
time validation rejects it.

```
FORGE=1 docker compose up -d attacker
sleep 3
docker compose restart resolver
sleep 4
docker compose exec client dig @172.16.2.10 example.com | grep -E "status:"
docker compose exec client curl -s --max-time 5 http://example.com   
```

The lookup now returns `status: SERVFAIL` and curl can't reach anything, no rogue
page this time. To see why, and to prove the attacker really is still forging:

```
docker compose logs resolver --no-log-prefix | grep -iE "no valid signature|RRSIG failed" | tail -2
docker compose logs attacker --no-log-prefix | grep FORGED | tail -1
```

The resolver logs `no valid signature found` and `RRSIG failed to verify … example.com/A`,
while the attacker still logs `FORGED example.com A -> 172.16.1.30`. The attack is
unchanged and still live, it's just that the validating resolver catches the
mismatch and fails closed. Contrast with Phase 2, where the same forgery landed the
client on the rogue page. To go back to transparent, `FORGE=0 docker compose up -d
attacker` and flush again.

## Capturing evidence

The four screenshots in `evidence/` cover the full story: the three zones signed,
the legitimate validated lookup with the ad flag, the attack coming back SERVFAIL,
and the resolver's RRSIG-failure log sitting next to the attacker's FORGED line.

```
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"   # 01
docker compose exec client dig +dnssec @172.16.2.10 example.com                           # 02
docker compose exec client delv -a /signed/root-anchor.conf @172.16.2.10 example.com      # 02
docker compose exec client dig @172.16.2.10 example.com | grep -E "status:"               # 03
docker compose logs resolver --no-log-prefix | grep -iE "no valid signature|RRSIG failed" # 04
docker compose logs attacker --no-log-prefix | grep FORGED                                # 04
```
