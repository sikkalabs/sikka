#!/bin/bash
# Docker entrypoint: prepare Tor HS keys, run tor + sikka-node, supervise Tor.
set -euo pipefail

DATA_DIR="/data"
TORRC="${DATA_DIR}/torrc"
SOCKS="127.0.0.1:9050"
SOCKS_PORT="9050"

TOR_PID=""
NODE_PID=""
TOR_RESTARTS=0
TOR_RESTART_WINDOW_START=0
MAX_TOR_RESTARTS=5
TOR_RESTART_WINDOW_SECS=300

cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
    kill "${NODE_PID}" 2>/dev/null || true
    wait "${NODE_PID}" 2>/dev/null || true
  fi
  if [[ -n "${TOR_PID}" ]] && kill -0 "${TOR_PID}" 2>/dev/null; then
    kill "${TOR_PID}" 2>/dev/null || true
    wait "${TOR_PID}" 2>/dev/null || true
  fi
  exit "${code}"
}
trap cleanup EXIT INT TERM

start_tor() {
  echo "sikka: starting tor (SOCKS ${SOCKS})"
  tor -f "${TORRC}" &
  TOR_PID=$!
}

socks_up() {
  (echo >/dev/tcp/127.0.0.1/"${SOCKS_PORT}") >/dev/null 2>&1
}

wait_for_socks() {
  echo "sikka: waiting for Tor SOCKS on ${SOCKS}"
  local i
  for i in $(seq 1 120); do
    if socks_up; then
      echo "sikka: Tor SOCKS is up"
      return 0
    fi
    if ! kill -0 "${TOR_PID}" 2>/dev/null; then
      echo "sikka: tor exited before SOCKS was ready" >&2
      return 1
    fi
    sleep 1
  done
  echo "sikka: Tor SOCKS did not become ready within 120s" >&2
  return 1
}

restart_tor() {
  local now
  now="$(date +%s)"
  if (( now - TOR_RESTART_WINDOW_START > TOR_RESTART_WINDOW_SECS )); then
    TOR_RESTART_WINDOW_START="${now}"
    TOR_RESTARTS=0
  fi
  TOR_RESTARTS=$((TOR_RESTARTS + 1))
  if (( TOR_RESTARTS > MAX_TOR_RESTARTS )); then
    echo "sikka: tor died too often (${TOR_RESTARTS}/${MAX_TOR_RESTARTS} in ${TOR_RESTART_WINDOW_SECS}s); exiting" >&2
    return 1
  fi
  echo "sikka: tor died; restarting (${TOR_RESTARTS}/${MAX_TOR_RESTARTS})" >&2
  wait "${TOR_PID}" 2>/dev/null || true
  start_tor
  wait_for_socks
}

echo "sikka: preparing Tor hidden service keys"
ADVERTISE="$(/usr/local/bin/sikka-node --prepare-tor 2>/dev/null | tail -n1)"
echo "sikka: advertising ${ADVERTISE}"

mkdir -p "${DATA_DIR}/tor-data"
# Do not pre-create the HS dir world-readable — prepare-tor sets mode 0700.

start_tor
wait_for_socks

echo "sikka: starting sikka-node"
/usr/local/bin/sikka-node &
NODE_PID=$!

while true; do
  if ! kill -0 "${NODE_PID}" 2>/dev/null; then
    set +e
    wait "${NODE_PID}"
    code=$?
    set -e
    echo "sikka: sikka-node exited (code ${code})" >&2
    exit "${code}"
  fi
  if ! kill -0 "${TOR_PID}" 2>/dev/null; then
    restart_tor
  fi
  sleep 2
done
