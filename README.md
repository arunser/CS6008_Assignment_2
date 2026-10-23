# CS6008 Assignment 2: DNS Security

An isolated DNS hierarchy built in Docker, then attacked and defended across seven
phases, from a plaintext baseline, through on-path forgery, up to DNSSEC and
DNS-over-TLS. Each phase has its own directory with a self-contained README,
reproducible commands, and evidence; this file is the map.

## Topology

Three subnets joined only by two router containers, no NAT, static routes:

- **client** `172.16.1.0/24`, with the client, the real webserver (`.20`), the rogue
  webserver (`.30`)
- **resolver** `172.16.2.0/24`, with the recursive, validating BIND resolver (`.10`)
- **authoritative** `172.16.3.0/24`, with root (`.10`), `com` TLD (`.20`), `example.com`
  domain (`.30`)

The **edge-router** bridges client↔resolver, the **core-router** bridges
resolver↔authoritative. They are the only path between subnets, which is what lets a
single on-path node be placed and studied.

## The seven phases

| Phase | Attack | Defense / lesson |
|-------|--------|------------------|
| 1 | none (baseline) | Plaintext resolution; the Root→TLD→Domain referral is fully readable on the wire |
| 2 | On-path response forgery (libpcap interceptor) | Plain DNS has no integrity; an on-path node rewrites answers at will |
| 3 | Same forgery, now vs DNSSEC | Signed zones + a validating resolver reject the forgery (SERVFAIL) |
| 4 | Signature stripping / downgrade | The parent's **DS** is what forces signatures; a missing DS reopens the attack |
| 5 | NSEC zone-walking (libpcap walker) | Signed denial leaks the zone; **NSEC3** (hashed denial) closes the walk |
| 6 | Last-mile forgery (stub vs validating client) | Resolver-side validation doesn't protect a stub; local validation does |
| 7 | Block / rogue **DoT** MITM | DNS-over-TLS + a private CA encrypt and authenticate the last mile |

Each phase (3 onward) reuses the signed hierarchy and the carried-over attacker from
the previous one, so the defense changes, not the attacker.

## Prerequisites

- Docker + Docker Compose
- Wireshark (for the packet captures referenced in the phase READMEs)

All attack tooling is C + libpcap (no Scapy/dnspython), compiled inside the attacker
image at build time. The DNSSEC keys and TLS certs are generated at deploy into Docker
volumes, so no private key material is committed.

## Running a phase

Each phase is independent. From its directory:

```
cd phaseN
docker compose up -d --build
# follow that phase's README for the verify + attack steps
```

Phases 3 to 7 sign the hierarchy bottom-up (root signs last), so the deploy waits a few
seconds and checks for the three "signed by itself" lines before verifying. Each phase
uses its own Compose project name (`cs6008-phaseN`) and the same container names, so
**tear down one phase before starting the next**:

```
docker compose down -v
```
