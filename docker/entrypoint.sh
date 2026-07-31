#!/bin/bash
# SIKKA container entrypoint: Tor is the peer mesh; the node speaks plain HTTP
# on localhost and Tor publishes it as a v3 onion derived from the node key.
set -euo pipefail

DATA_DIR="${SIKKA_DATA_DIR:-/data}"
KEYSTORE="${SIKKA_KEYSTORE:-$DATA_DIR/node_key.json}"
TOR_DATA="$DATA_DIR/tor/data"
TOR_HS="$DATA_DIR/tor/hs"
TOR_RC="$DATA_DIR/tor/torrc"
TOR_LOG="$DATA_DIR/tor/notice.log"
SOCKS_ADDR="127.0.0.1:9050"
# First-time Tor bootstrap on a slow link/Pi can take several minutes.
TOR_READY_TIMEOUT_SECS="${SIKKA_TOR_READY_TIMEOUT_SECS:-300}"

mkdir -p "$TOR_DATA" "$TOR_HS"
chmod 700 "$TOR_DATA" "$TOR_HS"
: > "$TOR_LOG"
chmod 600 "$TOR_LOG"

# Materialise ML-DSA key (and deterministic onion keys) before Tor starts.
sikka --key "$KEYSTORE" tor-prepare --dir "$TOR_HS"
chmod 700 "$TOR_HS"
chmod 600 "$TOR_HS/hs_ed25519_secret_key" 2>/dev/null || true
ONION="$(tr -d '[:space:]' < "$TOR_HS/hostname")"
if [ -z "$ONION" ]; then
  echo "entrypoint: missing onion hostname in $TOR_HS/hostname" >&2
  exit 1
fi

ADVERTISE="http://${ONION}"
# Mesh identity is always the onion from this node's key — ignore any host-set
# SIKKA_ADVERTISE so an operator cannot advertise the wrong endpoint.
if [ -n "${SIKKA_ADVERTISE:-}" ] && [ "$SIKKA_ADVERTISE" != "$ADVERTISE" ]; then
  echo "entrypoint: ignoring SIKKA_ADVERTISE=${SIKKA_ADVERTISE} (using derived onion)" >&2
fi
export SIKKA_ADVERTISE="$ADVERTISE"
export SIKKA_TOR_PROXY="socks5h://${SOCKS_ADDR}"
export SIKKA_KEYSTORE="$KEYSTORE"

cat > "$TOR_RC" <<EOF
DataDirectory $TOR_DATA
SocksPort $SOCKS_ADDR
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
AvoidDiskWrites 0
HiddenServiceDir $TOR_HS
HiddenServicePort 64552 127.0.0.1:64552
Log notice file $TOR_LOG
EOF

echo "entrypoint: onion ${ONION}"
echo "entrypoint: advertise ${SIKKA_ADVERTISE}"
echo "entrypoint: socks ${SIKKA_TOR_PROXY}"
echo "entrypoint: tor log ${TOR_LOG}"

tor -f "$TOR_RC" &
TOR_PID=$!

cleanup() {
  kill "$TOR_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

tor_bootstrapped() {
  grep -q 'Bootstrapped 100%' "$TOR_LOG" 2>/dev/null
}

socks_open() {
  (echo >/dev/tcp/127.0.0.1/9050) >/dev/null 2>&1
}

echo "entrypoint: waiting for Tor mesh (up to ${TOR_READY_TIMEOUT_SECS}s)…"
READY=0
for i in $(seq 1 "$TOR_READY_TIMEOUT_SECS"); do
  if ! kill -0 "$TOR_PID" 2>/dev/null; then
    echo "entrypoint: tor exited before becoming ready" >&2
    tail -n 40 "$TOR_LOG" >&2 || true
    wait "$TOR_PID" || true
    exit 1
  fi
  if tor_bootstrapped && socks_open; then
    READY=1
    echo "entrypoint: Tor ready after ${i}s (Bootstrapped 100%)"
    break
  fi
  # Progress every 30s so operators know we are not stuck silently.
  if [ $((i % 30)) -eq 0 ]; then
    LAST="$(grep 'Bootstrapped' "$TOR_LOG" 2>/dev/null | tail -n 1 || true)"
    if [ -n "$LAST" ]; then
      echo "entrypoint: still waiting… ${LAST}"
    else
      echo "entrypoint: still waiting… ${i}s (no bootstrap line yet)"
    fi
  fi
  sleep 1
done

if [ "$READY" -ne 1 ]; then
  echo "entrypoint: Tor did not reach Bootstrapped 100% within ${TOR_READY_TIMEOUT_SECS}s" >&2
  tail -n 80 "$TOR_LOG" >&2 || true
  exit 1
fi

echo "entrypoint: mesh ready · onion=${ONION} · socks=${SOCKS_ADDR}"
exec sikka-node
