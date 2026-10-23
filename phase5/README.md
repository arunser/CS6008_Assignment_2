# Phase 5: NSEC zone walking

This builds on Phase 3's signed hierarchy. DNSSEC has to prove that a name doesn't
exist, and with plain NSEC it does that by pointing at the next existing name in the
zone. Chased end to end, those "next name" pointers spell out the whole zone. So this
phase enumerates example.com from the outside, then fixes the leak with NSEC3.

The new piece is a second libpcap tool, walker.c, built alongside the interceptor.
Starting from example.com alone, it queries a name's NSEC, reads the next name it
points to, queries that, and follows the chain until it wraps back to the apex. It
talks to domain-ns directly through the core-router, using only DNS queries, no AXFR
and no wordlist. The signer takes an NSEC3 toggle, already built in, for the fix.

## Build and run

Scaffolded from Phase 3, with walker.c added to the attacker image. Deploy is the
standard signed hierarchy, which signs with plain NSEC by default.

```
docker compose up -d --build
sleep 15
docker compose up -d
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"
```

## Verify the denial is authenticated

A name that doesn't exist comes back as an authenticated NXDOMAIN.

```
docker compose exec client dig @172.16.2.10 doesnotexist.example.com +dnssec | grep -E "status:|flags:"
```

status NXDOMAIN with the ad flag. The denial itself is signed, carried by NSEC
records in the authority section. That's exactly what the walker reads.

## Walk the zone

```
docker compose exec attacker walker
```

The walker recovers the whole zone, db, dev, internal, mail, ns, vpn, www, in 8
queries. Each NSEC names the next existing owner to prove the gap between them is
empty, so the records chain into a sorted list of every name. Plain DNS doesn't leak
like this, its NXDOMAIN names no neighbour.

## Apply the fix, NSEC3

Re-sign example.com with NSEC3 (hashed denial) and walk again. The switch is at sign
time, so it needs a clean down -v.

```
docker compose down -v
NSEC3=1 docker compose up -d --build
sleep 15
docker compose up -d
docker compose exec client dig @172.16.2.10 doesnotexist.example.com +dnssec | grep -E "status:|flags:"
docker compose exec attacker walker | tail -3
```

The denial still authenticates (NXDOMAIN + ad), but the walker now has nothing to
follow and recovers 0 names. NSEC3 hashes the names before chaining, so an online
walk yields only hashes. It costs extra signing and validation and larger responses,
and the hashes can still be harvested and cracked offline against a wordlist, so it
raises the bar rather than closing enumeration completely.

## Capturing evidence

The screenshots in evidence/ cover the authenticated denial, the NSEC walk recovering
all seven names, the NSEC3 re-sign, and the walk coming up empty under NSEC3.

```
docker compose exec client dig @172.16.2.10 doesnotexist.example.com +dnssec | grep -E "status:|flags:"   # 01
docker compose exec attacker walker                                                                        # 02
# re-sign with NSEC3 (down -v; NSEC3=1 up -d --build), then:                                                # 03
docker compose exec attacker walker | tail -3                                                              # 04
```
