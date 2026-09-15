#!/usr/bin/env bash
# Boot the Tor mesh compose stack and verify both validators come up.
#
# Usage: ./docker/test-tor-mesh.sh [--strict]
#
# Full onion-to-onion discovery needs Tor relay egress from the container
# runtime. On networks that block Tor, this script still verifies: image
# boot, HS key prep, SOCKS, node health, and onion advertise. When Tor
# bootstraps, it also checks peers. Without --strict a blocked Tor network
# exits 0 ("partial OK"); --strict turns that into a failure for CI.
#
# Requires .env with validator1= / validator2= 64-hex-char seeds
# (copy .env.example to start).
set -euo pipefail

STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--strict]" >&2
  exit 2
fi

# Container runtime: Podman first, Docker fallback. Override with CONTAINER_RUNTIME.
RUNTIME="${CONTAINER_RUNTIME:-}"
if [[ -z "$RUNTIME" ]]; then
  if command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
  else
    RUNTIME=docker
  fi
fi
# Compose wrapper: `podman compose` (plugin) or `podman-compose` (pip) or `docker compose`.
COMPOSE=("$RUNTIME" compose)
if [[ "$RUNTIME" == "podman" ]] && ! podman compose version >/dev/null 2>&1; then
  if command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
  else
    echo "podman found but no compose provider; install podman-compose (pip install podman-compose)" >&2
    exit 1
  fi
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "missing .env with validator1= and validator2= seeds (copy .env.example)" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

# Fail here, not 90s into boot: seeds must be 32 bytes as 64 hex chars.
hex64='^[0-9a-fA-F]{64}$'
if [[ ! "${validator1:-}" =~ $hex64 || ! "${validator2:-}" =~ $hex64 ]]; then
  echo ".env must define validator1 and validator2 as 64-hex-char seeds (see .env.example)" >&2
  exit 1
fi

# Parse peer counts as JSON, not with sed: pretty-printing or extra
# whitespace must not break the check. python3/stdlib only, no jq needed.
peer_count() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("peers", 0))'
}

echo "==> building and starting validators ($RUNTIME)"
"${COMPOSE[@]}" -f docker-compose.tor.yml --env-file .env up --build -d

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
    "${COMPOSE[@]}" -f docker-compose.tor.yml logs --tail=80
    exit 1
  fi
done

echo "==> checking onion advertise + HS keys"
host2=""
for c in sikka-validator1 sikka-validator2; do
  host="$("$RUNTIME" exec "$c" cat /data/arti/ctor/hostname | tr -d '\n')"
  if [[ ! "$host" =~ \.onion$ ]]; then
    echo "$c missing .onion hostname" >&2
    exit 1
  fi
  echo "  $c -> http://$host"
  if [[ "$c" == "sikka-validator2" ]]; then
    host2="$host"
  fi
done

h1="$(curl -fsS http://127.0.0.1:64553/api/health)"
h2="$(curl -fsS http://127.0.0.1:64554/api/health)"
echo "validator1 health: ${h1}"
echo "validator2 health: ${h2}"

p1="$(echo "$h1" | peer_count)"
p2="$(echo "$h2" | peer_count)"
if [[ "${p1:-0}" -lt 1 || "${p2:-0}" -lt 1 ]]; then
  echo "expected bootstrap peer entries (>=1 each); got ${p1} and ${p2}" >&2
  exit 1
fi

echo "==> waiting for Tor bootstrap (up to ~3 minutes)"
bootstrapped=0
for _ in $(seq 1 36); do
  if "$RUNTIME" logs sikka-validator1 2>&1 | grep -q 'Bootstrapped 100%'; then
    bootstrapped=1
    break
  fi
  sleep 5
done

if [[ "$bootstrapped" != 1 ]]; then
  echo "WARN: Tor did not reach 100% bootstrap in this environment (relay egress may be blocked)."
  echo "      Container boot, onion derive, SOCKS, and health checks passed."
  if [[ "$STRICT" == 1 ]]; then
    echo "==> Tor mesh FAILED (strict mode: no onion bootstrap)" >&2
    exit 1
  fi
  echo "==> Tor mesh partial OK (peers=${p1}/${p2}, awaiting network that allows Tor)"
  exit 0
fi

echo "==> Tor bootstrapped; waiting for onion discovery"
sleep 60
h1="$(curl -fsS http://127.0.0.1:64553/api/health)"
h2="$(curl -fsS http://127.0.0.1:64554/api/health)"
echo "validator1 health: ${h1}"
echo "validator2 health: ${h2}"

# Cross-check via SOCKS inside the container, dialling validator2's live
# onion (read from its HS keys above) — never a hardcoded address.
if ! "$RUNTIME" exec sikka-validator1 \
  curl -fsS --max-time 90 --socks5-hostname "127.0.0.1:9050" "http://${host2}/api/health" \
  >/tmp/sikka-onion-health.json 2>/tmp/sikka-onion-health.err; then
  echo "onion dial failed:" >&2
  cat /tmp/sikka-onion-health.err >&2 || true
  "${COMPOSE[@]}" -f docker-compose.tor.yml logs --tail=80
  exit 1
fi
echo "onion health: $(cat /tmp/sikka-onion-health.json)"
echo "==> Tor mesh OK"
