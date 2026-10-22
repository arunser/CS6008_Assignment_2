# Phase 1 — DNS hierarchy

This phase builds the DNS setup that everything else in the assignment runs on
top of: a root server, a `.com` server, and the `example.com` server, plus a
recursive resolver and a client that actually does the lookups. All of it runs
in containers spread across three Docker networks, and the only way to get from
one network to another is through the two router containers

## Topology

Three subnets, nothing directly connected between them:

| Node        | Network        | Address        | What it does                         |
|-------------|----------------|----------------|--------------------------------------|
| client      | client         | 172.16.1.10    | runs the dig/curl lookups            |
| webserver   | client         | 172.16.1.20    | serves the example.com page over HTTP|
| resolver    | resolver       | 172.16.2.10    | recursive resolver (DNSSEC off here) |
| root-ns     | authoritative  | 172.16.3.10    | authoritative for `.`                |
| tld-ns      | authoritative  | 172.16.3.20    | authoritative for `com`              |
| domain-ns   | authoritative  | 172.16.3.30    | authoritative for `example.com`      |
| edge-router | client+resolver| 172.16.1.2 / 172.16.2.2 | forwards client <-> resolver|
| core-router | resolver+auth  | 172.16.2.3 / 172.16.3.3 | forwards resolver <-> auth  |

Subnets: client `172.16.1.0/24`, resolver `172.16.2.0/24`, authoritative
`172.16.3.0/24`.

## What you need

A normal Docker install with Compose and Buildx, able to run containers with
added capabilities (the routers and leaf nodes use NET_ADMIN). The host tools I
used for checking are `dig`, `curl` and Wireshark/`tcpdump`. First run pulls the
BIND 9.20 and nginx images and builds a small Alpine image for the client and
routers.

## Bring it up

From this directory:

```
docker compose up -d --build
```

Give it a few seconds, then confirm the nameservers loaded their zones:

```
docker compose ps
docker compose logs root-ns tld-ns domain-ns resolver | grep -Ei "loaded serial|error"
```

Each of the three zones should load with serial `2026102201` and no errors.

## Verify it works

Resolution, from the client:

```
docker compose exec client dig @172.16.2.10 example.com
docker compose exec client dig +short www.example.com
docker compose exec client curl -s http://example.com
```

Both names come back as `172.16.1.20` and curl returns the webserver's page.
(Plain `dig example.com` goes through Docker's embedded resolver at 127.0.0.11,
which forwards to our resolver, so I query `@172.16.2.10` directly when I want
the output to show our resolver answering.)

Isolation check — the client must not be able to reach the authoritative subnet
on its own:

```
docker compose exec client dig @172.16.3.10 example.com +time=2 +tries=1
```

This times out, which is what we want. The only route to `172.16.3.0/24` is
through core-router, and the client doesn't have one.

The static routes each node uses:

```
docker compose exec resolver ip route | grep 172.16.3
docker compose exec client ip route | grep 172.16.2
```

## Capturing the referral chain

Capture on core-router, on the interface facing the authoritative subnet
(`eth1`):

```
docker compose exec core-router tcpdump -ni eth1 -w /tmp/p1.pcap port 53
```

In a second terminal, clear the resolver cache and trigger one lookup so the
whole walk happens fresh:

```
docker compose restart resolver
sleep 2
docker compose exec client dig @172.16.2.10 example.com
```

Stop tcpdump (Ctrl-C) and pull the capture out:

```
docker compose cp core-router:/tmp/p1.pcap ./evidence/p1_referral.pcap
```

Open it in Wireshark with a `dns` filter. You can follow the resolver asking the
root (which hands back the `com` delegation), then the com server (which hands
back the `example.com` delegation), then the example.com server (which finally
answers with the A record `172.16.1.20`). The saved capture is in `evidence/`.
