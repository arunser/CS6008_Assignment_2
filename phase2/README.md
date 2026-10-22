# Phase 2: On-path response forgery

This builds on Phase 1. Same DNS hierarchy and the same isolated subnets, but now
there's an attacker sitting on the resolver's subnet that can rewrite the
resolver's replies. The goal is to poison one name: make example.com resolve to a
rogue web server while every other lookup keeps working normally.

Three things are added on top of Phase 1:

- an **attacker** container (172.16.2.100) running a small C/libpcap interceptor,
- a **rogue-web** server (172.16.1.30) serving a defaced page,
- a route on **core-router** that sends the resolver's inbound replies through the
  attacker.

The resolver and the nameservers are left exactly as they were in Phase 1, the
diversion is only a route on the router. The attacker relays all DNS traffic
as-is except for example.com, where it swaps the A record to point at the rogue
server. Tooling is the same as Phase 1 (Docker + Compose, dig/curl, Wireshark).

## Build and run

From this directory. The build compiles the interceptor into the attacker image.
`FORGE` defaults to 0, so forging starts off.

```
docker compose up -d --build
docker compose logs attacker --no-log-prefix | grep "interceptor up"
```

You should get a line like `interceptor up: FORGE=0, resolver 172.16.2.10 at <mac>`.

## Check the relay is transparent (forging off)

With forging off the interceptor just passes everything through, so resolution
still returns the real server. Restart the resolver first to clear its cache.

```
docker compose restart resolver
sleep 4
docker compose exec client dig +short @172.16.2.10 example.com
docker compose exec client curl -s http://example.com
```

example.com comes back as 172.16.1.20 and curl returns the real page. I flush the
cache by restarting the resolver because this setup mounts its own config over the
image's /etc/bind, so rndc isn't available. The sleep gives the interceptor a
second to re-learn the resolver's MAC after the restart.

## Run the attack

Turn forging on (this recreates just the attacker), flush the cache again, then
look up example.com and www.

```
FORGE=1 docker compose up -d attacker
sleep 3
docker compose restart resolver
sleep 4
docker compose exec client dig +short @172.16.2.10 example.com      # -> 172.16.1.30
docker compose exec client dig +short @172.16.2.10 www.example.com  # -> 172.16.1.20
docker compose exec client curl -s http://example.com               # -> the rogue page
```

example.com now resolves to the rogue server (172.16.1.30) and curl returns the
HACKED page, while www.example.com is left untouched at 172.16.1.20. To switch
back to transparent, `FORGE=0 docker compose up -d attacker` and flush again.

## Capturing evidence

The attacker has tcpdump. Capture on its interface while a forged lookup happens:

```
docker compose exec attacker tcpdump -nni eth0 -w /tmp/atk.pcap "udp port 53"
```

In another terminal restart the resolver, wait, and do the lookup. Stop tcpdump,
then copy the capture out:

```
docker compose cp attacker:/tmp/atk.pcap ./evidence/p2_forgery.pcap
```

Open it in Wireshark. You can follow the genuine example.com answer (A 172.16.1.20)
coming in from domain-ns and the forged one (A 172.16.1.30) going back out with the
same query ID. The attacker also prints a FORGED line for each hijacked lookup —
`docker compose logs attacker --no-log-prefix | grep FORGED`.
