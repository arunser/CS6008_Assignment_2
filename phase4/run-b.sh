#!/bin/sh
# Run B -- example.com stays fully signed, but com publishes NO DS for it, so the
# resolver treats it as insecure and accepts the stripped forgery.
set -e
cd "$(dirname "$0")"

docker compose down -v
NODS=1 docker compose up -d --build           # com signs itself but withholds example.com's DS
sleep 15
NODS=1 docker compose up -d                   # stragglers (keep NODS so tld-ns isn't recreated)
docker compose logs root-ns tld-ns domain-ns --no-log-prefix | grep "signed by itself"

STRIP=1 docker compose up -d attacker         # engage strip mode AFTER the stragglers
sleep 3
docker compose restart resolver; sleep 4

echo "== client receives =="
docker compose exec client dig +short @172.16.2.10 example.com
docker compose exec client curl -s --max-time 5 http://example.com; echo
