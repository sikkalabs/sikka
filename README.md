# SIKKA

The simplest cryptocurrency for humans, AI agents, and micropayments.

**0% fees. No transaction history. Private by default.**

Named after *sikkā* — the Punjabi word for coin in the history of
[Sikh coinage](https://en.wikipedia.org/wiki/Sikh_coinage), borrowed from
Persian, where it meant both a die for minting and, by extension, the
authority to coin money.

Nodes keep balances, not ledgers of every payment. Consensus signs the state
root, then discards the transactions. Storage grows with accounts — not with
every transfer ever made.

[Website](https://sikkalabs.com/) ·
[Live node](https://1.sikkalabs.com/) ·
[Wallet](https://1.sikkalabs.com/wallet.html) ·
[Image](https://github.com/sikkalabs/sikka/pkgs/container/sikka)

---

## Quickstart (Podman)

Prerequisites: [Podman](https://podman.io/) 4+. No Rust toolchain needed to
run a node. Every `podman` command below also works with `docker` as a
drop-in replacement.

```bash
# 1. Pull the prebuilt image (amd64 + arm64)
podman pull ghcr.io/sikkalabs/sikka:latest

# 2. Run a node — only the seed is required
podman run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<32-byte-seed-hex> \
  ghcr.io/sikkalabs/sikka:latest

# 3. Check it
podman logs -f sikka
curl -s http://127.0.0.1:64552/api/health
open http://127.0.0.1:64552/wallet.html  # browser wallet on this node
```

Peer mesh is Tor-only (built into the image) — no ports to open, no domain
to configure. The onion address is derived automatically from
`SIKKA_PRIVATE_KEY`. Optional clearnet for wallets is just a reverse proxy
in front of port **64552**.

> **SELinux (Fedora / RHEL):** append `:Z` to the volume flag
> (`-v sikka-data:/data:Z`) so the rootless container can write `/data`.

Full ops guide: [`docs/docker.md`](docs/docker.md) ·
Stake your node: [`docs/staking.md`](docs/staking.md).

---

## Development

```bash
# Rust toolchain (matches CI + container builds)
rustup toolchain install 1.90
rustup default 1.90

# Fast native checks (no container needed)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Container builds with Podman (same `Dockerfile`, OCI-compatible):

```bash
# Production node image
podman build -t ghcr.io/sikkalabs/sikka:latest .

# Test image — runs the whole suite inside the container,
# so a green run means green on any machine
podman build -f Dockerfile.test -t sikka-test .
podman run --rm sikka-test
```

Useful container CLI (the image ships the `sikka` client, pre-pointed at
the in-container node):

```bash
podman exec sikka sikka address
podman exec sikka sikka balance --verify
podman exec sikka sikka info
podman exec sikka sikka validators
podman exec sikka sikka send <to-address> 10 --wait
podman exec sikka sikka bond 400
```

Stop / wipe:

```bash
podman stop sikka && podman rm sikka
podman volume rm sikka-data   # deletes chain state + keys
```

---

## Testing

| What | Command | Notes |
| --- | --- | --- |
| Unit + integration (host) | `cargo test --workspace --locked` | Same command CI runs; `Cargo.toml` already raises test `opt-level` because ML-DSA-87 is too slow in debug |
| Full suite (container) | `podman build -f Dockerfile.test -t sikka-test . && podman run --rm sikka-test` | Unit tests + ledger/consensus integration + 4-node HTTP testnet on loopback; never touches the host |
| Lint / format | `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets --locked -- -D warnings` | Both enforced in CI |
| Local Tor mesh (2 validators) | `cp .env.example .env && ./docker/test-tor-mesh.sh [--strict]` | Seeds validated upfront as 64-hex; script auto-uses `podman` if `docker` is absent; `--strict` fails instead of partial-OK when Tor is blocked |

Tor mesh details:

```bash
# With podman-compose (or docker compose — same file):
podman-compose -f docker-compose.tor.yml --env-file .env up --build
# Without any compose plugin — plain Podman, equivalent:
podman network create sikka-mesh 2>/dev/null || true
podman run -d --name sikka-validator1 --network sikka-mesh \
  -p 64553:64552 -v v1-data:/data:Z -e SIKKA_PRIVATE_KEY=$validator1 \
  ghcr.io/sikkalabs/sikka:latest
podman run -d --name sikka-validator2 --network sikka-mesh \
  -p 64554:64552 -v v2-data:/data:Z -e SIKKA_PRIVATE_KEY=$validator2 \
  ghcr.io/sikkalabs/sikka:latest
curl -s http://127.0.0.1:64553/api/health
curl -s http://127.0.0.1:64554/api/health
```

Full onion-to-onion discovery needs outbound Tor access; where Tor relays
are blocked the script still verifies boot, HS key derivation, SOCKS, and
local health. See [`docs/docker.md`](docs/docker.md#local-tor-mesh-test-two-validators).

---

## Features

- **Zero fees** — send any amount without paying gas. Validators earn from
  fixed **1.5%/year** inflation on bonded stake.
- **No history** — finalized payments are thrown away. Only balances and the
  latest checkpoint remain on-chain.
- **Private by default** — without a permanent tx log, past payments are not
  publicly reconstructable. Peer mesh is Tor-only (signed JSON over onion
  HTTP); wallets may use an optional clearnet reverse proxy to the same node.
- **Built for micropayments** — feeless transfers and a regenerating spam battery (+1/min, cap 10) make high-frequency, low-value payments practical. Fresh accounts start at 0 battery to prevent funding-sybil attacks.
- **Agent-ready** — plain HTTP + JSON-RPC. One endpoint to check balances,
  send, and bond — no heavy SDKs required.
- **Post-quantum** — every signature is **ML-DSA-87** (FIPS 204); hashes are
  **SHA3-256**.
- **Proofs, not trust** — stateless light wallets verify inclusion and absence with Sparse Merkle Tree (SMT) proofs against the checkpoint root.
- **Instant fast-sync** — new or returning nodes catch up in seconds via state snapshots verified against $\ge$ 2/3 bonded stake without replaying historical transactions.
- **Deterministic inflation** — 1.5%/year inflation compounding is calculated using 128-bit integer fixed-point math (`expm1_fixed`), avoiding floating-point non-determinism across CPU architectures.
- **Non-punitive consensus** — round-robin proposer rotation with automatic 10-second timeout fallbacks. Downtime never burns stake; only double-signing (equivocation) is slashed. Validators that repeatedly miss full-batch proposer turns are forced into the normal unbonding cooldown (default: 100 consecutive misses; configurable in genesis). Inflation each round is shared across the active bonded set (bond-weighted), independent of which exact quorum certificate sealed the prior checkpoint.
- **Efficient mempool sync** — nodes exchange compact Bloom filters during peer reconciliation to request only missing transactions, minimizing network bandwidth.
- **Pure-Rust storage** — built on `redb` (ACID key-value store) with 3 fixed tables (`accounts`, `validators`, `meta`), requiring zero C/C++ database dependencies.
- **Simple ops** — one container, one published port, set `SIKKA_PRIVATE_KEY`.
  Tor onion advertise is derived automatically. Containers (Podman first,
  Docker compatible) are the production path.

---

## At a glance

| | |
| --- | --- |
| Genesis supply | **19,960,907** SIKKA (1 SIKKA = 10⁹ CHILLAR) |
| Consensus | Checkpoint voting · ≥2/3 bonded stake · round-robin proposer |
| Spam control | Battery (+1/min, cap 10, 1 per tx) |
| Transport | Signed JSON over HTTP · Tor-only peer mesh (optional clearnet for wallets) |
| Containers | Podman (Docker-compatible) · `ghcr.io/sikkalabs/sikka:latest` |
| Repo | [github.com/sikkalabs/sikka](https://github.com/sikkalabs/sikka) |

---

## Docs

- Whitepaper: [`docs/whitepaper.md`](docs/whitepaper.md)
- Run a node: [`docs/docker.md`](docs/docker.md) (Podman commands work 1:1)
- Stake a node: [`docs/staking.md`](docs/staking.md)
- Wallets: [`docs/wallets.md`](docs/wallets.md)
- HTTP + JSON-RPC: [`docs/api.md`](docs/api.md)
