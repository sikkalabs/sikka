# SIKKA

The simplest cryptocurrency for humans, AI agents, and micropayments.

**0% fees. No transaction history. Private by default.**

Nodes keep balances, not ledgers of every payment. Consensus signs the state
root, then discards the transactions. Storage grows with accounts — not with
every transfer ever made.

[Website](https://sikkalabs.com/) ·
[Live node](https://1.sikkalabs.com/) ·
[Wallet](https://1.sikkalabs.com/wallet.html) ·
[Image](https://github.com/sikkalabs/sikka/pkgs/container/sikka)

---

## Features

- **Zero fees** — send any amount without paying gas. Validators earn from
  fixed **1.5%/year** inflation on bonded stake.
- **No history** — finalized payments are thrown away. Only balances and the
  latest checkpoint remain on-chain.
- **Private by default** — without a permanent tx log, past payments are not
  publicly reconstructable. **Tor is the peer mesh**: every node image publishes
  a v3 onion derived from its key; users still open any node over plain HTTP.
- **Built for micropayments** — feeless transfers and regenerating spam credits (+1/min, cap 100) make high-frequency, low-value payments practical. Fresh accounts start at 0 credits to prevent funding-sybil attacks.
- **Agent-ready** — plain HTTP + JSON-RPC. One endpoint to check balances,
  send, and bond — no heavy SDKs required.
- **Post-quantum** — every signature is **ML-DSA-87** (FIPS 204); hashes are
  **SHA3-256**.
- **Proofs, not trust** — stateless light wallets verify inclusion and absence with Sparse Merkle Tree (SMT) proofs against the checkpoint root.
- **Instant fast-sync** — new or returning nodes catch up in seconds via state snapshots verified against $\ge$ 2/3 validator signatures without replaying historical transactions.
- **Deterministic inflation** — 1.5%/year inflation compounding is calculated using 128-bit integer fixed-point math (`expm1_fixed`), avoiding floating-point non-determinism across CPU architectures.
- **Non-punitive consensus** — round-robin proposer rotation with automatic 10-second timeout fallbacks. Downtime never burns stake; only double-signing (equivocation) is slashed. Inflation each round goes to validators that signed the previous checkpoint.
- **Efficient mempool sync** — nodes exchange compact Bloom filters during peer reconciliation to request only missing transactions, minimizing network bandwidth.
- **Pure-Rust storage** — built on `redb` (ACID key-value store) with 3 fixed tables (`accounts`, `validators`, `meta`), requiring zero C/C++ database dependencies.
- **Simple ops** — one container (Tor + node), one optional published port for
  wallets. Docker is the production path.

---

## At a glance

| | |
| --- | --- |
| Genesis supply | **19,960,907** SIKKA (1 SIKKA = 10⁹ CHILLAR) |
| Consensus | Checkpoint voting · ≥2/3 bonded stake · round-robin proposer |
| Spam control | Credits (+1/min, cap 100, 1 per tx) |
| Transport | Signed JSON over HTTP · Tor onion mesh between nodes |
| Repo | [github.com/sikkalabs/sikka](https://github.com/sikkalabs/sikka) |

---

## Docs

- Run a node: [`docs/docker.md`](docs/docker.md)
- Wallets: [`docs/wallets.md`](docs/wallets.md)
- HTTP + JSON-RPC: [`docs/api.md`](docs/api.md)
