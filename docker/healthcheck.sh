#!/bin/bash
# Container health: RPC up and Tor SOCKS accepting connections.
# Onion self-check (`tor.status`) can lag while HS descriptors publish, so we
# only require the SOCKS listener — dead Tor fails, slow publish does not.
set -euo pipefail

curl -fsS --max-time 4 http://127.0.0.1:64552/api/health >/dev/null
(echo >/dev/tcp/127.0.0.1/9050) >/dev/null 2>&1
