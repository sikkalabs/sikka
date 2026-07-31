#!/bin/bash
# SIKKA container entrypoint: Tor is the peer mesh; the node speaks plain HTTP
# on localhost and Tor publishes it as a v3 onion derived from the node key.
set -euo pipefail

DATA_DIR="${SIKKA_DATA_DIR:-/data}"
KEYSTORE="${SIKKA_KEYSTORE:-$DATA_DIR/node_key.json}"
TOR_DATA="$DATA_DIR/tor/data"
TOR_HS="$DATA_DIR/tor/hs"
TOR_RC="$DATA_DIR/tor/torrc"
SOCKS_ADDR="127.0.0.1:9050"

mkdir -p "$TOR_DATA" "$TOR_HS"
chmod 700 "$TOR_DATA" "$TOR_HS"

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
Log notice stdout
EOF

echo "entrypoint: onion ${ONION}"
echo "entrypoint: advertise ${SIKKA_ADVERTISE}"
echo "entrypoint: socks ${SIKKA_TOR_PROXY}"

tor -f "$TOR_RC" &
TOR_PID=$!

cleanup() {
  kill "$TOR_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait until SOCKS accepts connections (Tor finished bootstrapping enough).
for _ in $(seq 1 90); do
  if (echo >/dev/tcp/127.0.0.1/9050) >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$TOR_PID" 2>/dev/null; then
    echo "entrypoint: tor exited before SOCKS was ready" >&2
    wait "$TOR_PID" || true
    exit 1
  fi
  sleep 1
done

exec sikka-node
