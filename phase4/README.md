# Phase 4: Signature stripping and downgrade

This builds on Phase 3. Same signed hierarchy, same validating resolver, same
on-path attacker. Forging a signed answer failed in Phase 3 because the resolver
checks the signature, so here the attacker doesn't try to forge a signed record. It
strips the DNSSEC off example.com's answer and injects a plain forged A, trying to
make the signed zone look unsigned so the Phase 2 forgery is accepted again.

The only new thing is a strip mode on the interceptor. For example.com it rebuilds
the answer as one unsigned forged A with no RRSIG, and returns an empty answer for
the DNSKEY query and, when STRIPDS is on, the DS query, so the keys and the parent's
DS never reach the resolver. Everything else relays untouched. The signer and the
resolver are unchanged from Phase 3; the NODS toggle, already built into the
per-server signer, is what sets up Run B.

There are two runs, driven by run-a.sh and run-b.sh.

## Build and run

Scaffolded from Phase 3 (cp -r phase3 phase4), with the interceptor's strip mode
added and the STRIP/STRIPDS/NODS toggles wired into compose. Deploy is the standard
signed hierarchy. root-ns signs last, so give it the wait.

```
docker compose up -d --build
sleep 15
docker compose up -d
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"
```

Three "signed by itself" lines means the chain is up.

## Verify authenticated (before stripping)

With nothing stripping, example.com still resolves as an authenticated answer.

```
docker compose exec client dig +dnssec @172.16.2.10 example.com | grep -E "status:|flags:"
```

status NOERROR with the ad flag, and an RRSIG on the record. This is the Phase 3
baseline, the chain validates.

## Run A — strip with the chain intact

run-a.sh deploys clean, turns on strip mode, and looks example.com up. It strips
twice: first the RRSIG and DNSKEY, then a fuller downgrade that also strips the DS
(and its RRSIG) from the com referral.

```
./run-a.sh
```

Both come back status: SERVFAIL. The attacker logs `STRIPPED+forged … (unsigned)`
and the resolver logs `insecurity proof failed resolving example.com/A`. com holds a
signed DS for example.com, so the resolver knows the zone must be signed. It can't
accept an unsigned answer, and it can't build a proof that the zone is insecure, so
it refuses the whole lookup. Stripping on the wire can't erase what the parent
already vouched for.

## Run B — the missing DS reopens it

run-b.sh re-signs with NODS=1 so com publishes no DS for example.com (the operator
signed the child but never gave the DS to the parent) and mounts the same
strip-and-forge.

```
./run-b.sh
```

Now example.com resolves to 172.16.1.30 and curl returns the rogue page. The single
change is the missing DS: com authentically proves, signed, that example.com has no
secure delegation, so the resolver treats it as insecure, ignores its signatures,
and accepts the stripped forgery. One missing DS turns a protected zone into an
unprotected one. To switch back, ./run-a.sh redeploys the fully-chained hierarchy.

## Capturing evidence

The screenshots in evidence/ walk through both runs: the clean deploy, the
authenticated baseline with the ad flag, Run A coming back SERVFAIL with the
insecurity-proof and STRIPPED logs, and Run B landing on the rogue page.

```
docker compose exec client dig +dnssec @172.16.2.10 example.com | grep -E "status:|flags:"   # 01,02
./run-a.sh                                                                                    # 03,04
./run-b.sh                                                                                    # 05,06
```
