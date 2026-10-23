#!/bin/sh
# Run A -- strip the signatures with the DNSSEC chain intact. com holds a signed
# DS for example.com, so the resolver refuses the stripped/forged answer.
set -e
cd "$(dirname "$0")"
docker compose down -v
docker compose up -d --build
sleep 15
docker compose up -d
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"
echo "== strip RRSIG + DNSKEY, inject forged A =="
STRIP=1 docker compose up -d attacker
sleep 3
docker compose restart resolver; sleep 4
docker compose exec client dig @172.16.2.10 example.com | grep -E "status:"
docker compose logs attacker --no-log-prefix | grep STRIPPED | tail -1
docker compose logs resolver --no-log-prefix | grep -i "insecurity proof" | tail -1
echo "== fuller downgrade: also strip the DS from the com referral =="
STRIP=1 STRIPDS=1 docker compose up -d attacker
sleep 3
docker compose restart resolver; sleep 4
docker compose exec client dig @172.16.2.10 example.com | grep -E "status:"