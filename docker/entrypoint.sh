#!/bin/bash
# Docker entrypoint: prepare deterministic Tor HS keys, start tor, then sikka-node.
set -euo pipefail

DATA_DIR="/data"
TORRC="${DATA_DIR}/torrc"
SOCKS="127.0.0.1:9050"
SOCKS_PORT="9050"

echo "sikka: preparing Tor hidden service keys"
ADVERTISE="$(/usr/local/bin/sikka-node --prepare-tor 2>/dev/null | tail -n1)"
echo "sikka: advertising ${ADVERTISE}"

# tor may need to own its data directory
mkdir -p "${DATA_DIR}/tor-data"
# Do not pre-create the HS dir world-readable — prepare-tor sets mode 0700.

echo "sikka: starting tor (SOCKS ${SOCKS})"
tor -f "${TORRC}" &
TOR_PID=$!

cleanup() {
  if kill -0 "${TOR_PID}" 2>/dev/null; then
    kill "${TOR_PID}" 2>/dev/null || true
    wait "${TOR_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Wait until the SOCKS port accepts connections (Tor bootstrap can take a bit).
echo "sikka: waiting for Tor SOCKS on ${SOCKS}"
for _ in $(seq 1 120); do
  if (echo >/dev/tcp/127.0.0.1/"${SOCKS_PORT}") >/dev/null 2>&1; then
    echo "sikka: Tor SOCKS is up"
    break
  fi
  if ! kill -0 "${TOR_PID}" 2>/dev/null; then
    echo "sikka: tor exited early" >&2
    exit 1
  fi
  sleep 1
done

echo "sikka: starting sikka-node"
exec /usr/local/bin/sikka-node
