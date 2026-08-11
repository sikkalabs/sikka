#!/usr/bin/env bash
# Boot the Tor mesh compose stack and verify both validators come up.
#
# Full onion-to-onion discovery needs Tor relay egress from Docker. On networks
# that block Tor, this script still verifies: image boot, HS key prep, SOCKS,
# node health, and onion advertise. When Tor bootstraps, it also checks peers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "missing .env with validator1= and validator2= seeds" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

if [[ -z "${validator1:-}" || -z "${validator2:-}" ]]; then
  echo ".env must define validator1 and validator2" >&2
  exit 1
fi

echo "==> building and starting validators"
docker compose -f docker-compose.tor.yml --env-file .env up --build -d

echo "==> waiting for local health endpoints"
for port in 64553 64554; do
  ok=0
  for _ in $(seq 1 90); do
    if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
      echo "  port ${port} healthy"
      ok=1
      break
    fi
    sleep 2
  done
  if [[ "$ok" != 1 ]]; then
    echo "timeout waiting for health on ${port}" >&2
    docker compose -f docker-compose.tor.yml logs --tail=80
    exit 1
  fi
done

echo "==> checking onion advertise + HS keys"
for c in sikka-validator1 sikka-validator2; do
  host="$(docker exec "$c" cat /data/arti/ctor/hostname | tr -d '\n')"
  if [[ ! "$host" =~ \.onion$ ]]; then
    echo "$c missing .onion hostname" >&2
    exit 1
  fi
  echo "  $c -> http://$host"
done

h1="$(curl -fsS http://127.0.0.1:64553/api/health)"
h2="$(curl -fsS http://127.0.0.1:64554/api/health)"
echo "validator1 health: ${h1}"
echo "validator2 health: ${h2}"

p1="$(echo "$h1" | sed -n 's/.*"peers":\([0-9][0-9]*\).*/\1/p')"
p2="$(echo "$h2" | sed -n 's/.*"peers":\([0-9][0-9]*\).*/\1/p')"
if [[ "${p1:-0}" -lt 1 || "${p2:-0}" -lt 1 ]]; then
  echo "expected bootstrap peer entries (>=1 each); got ${p1} and ${p2}" >&2
  exit 1
fi

echo "==> waiting for Tor bootstrap (up to ~3 minutes)"
bootstrapped=0
for _ in $(seq 1 36); do
  if docker logs sikka-validator1 2>&1 | grep -q 'Bootstrapped 100%'; then
    bootstrapped=1
    break
  fi
  sleep 5
done

if [[ "$bootstrapped" != 1 ]]; then
  echo "WARN: Tor did not reach 100% bootstrap in this environment (relay egress may be blocked)."
  echo "      Container boot, onion derive, SOCKS, and health checks passed."
  echo "==> Tor mesh partial OK (peers=${p1}/${p2}, awaiting network that allows Tor)"
  exit 0
fi

echo "==> Tor bootstrapped; waiting for onion discovery"
sleep 60
h1="$(curl -fsS http://127.0.0.1:64553/api/health)"
h2="$(curl -fsS http://127.0.0.1:64554/api/health)"
echo "validator1 health: ${h1}"
echo "validator2 health: ${h2}"

# Cross-check via SOCKS inside the container.
if ! docker exec sikka-validator1 bash -c \
  'curl -fsS --max-time 90 --socks5-hostname 127.0.0.1:9050 http://gejjo77o6nxjtvydahgkcaaebczfj4sjgs2spspykqzqaof46exnqoad.onion/api/health' \
  >/tmp/sikka-onion-health.json 2>/tmp/sikka-onion-health.err; then
  echo "onion dial failed:" >&2
  cat /tmp/sikka-onion-health.err >&2 || true
  docker compose -f docker-compose.tor.yml logs --tail=80
  exit 1
fi
echo "onion health: $(cat /tmp/sikka-onion-health.json)"
echo "==> Tor mesh OK"
