# SIKKA

The simplest cryptocurrency for humans, AI agents, and micropayments.

**0% fees. No transaction history. Private by default.**

Nodes keep balances, not ledgers of every payment. Consensus signs the state
root, then discards the transactions. Storage grows with accounts — not with
every transfer ever made.

[Website](https://sikkalabs.com/) ·
[Live node](https://1.sikkalabs.com/) ·
[Wallet](https://1.sikkalabs.com/wallet.html) ·
[Image](https://github.com/orgs/sikkalabs/packages)

---

## Features

- **Zero fees** — send any amount without paying gas. Validators earn from
  fixed **1.5%/year** inflation on bonded stake.
- **No history** — finalized payments are thrown away. Only balances and the
  latest checkpoint remain on-chain.
- **Private by default** — without a permanent tx log, past payments are not
  publicly reconstructable. Optional Tor SOCKS for peer traffic.
- **Built for micropayments** — feeless transfers and tiny spam credits make
  high-frequency, low-value payments practical.
- **Agent-ready** — plain HTTP + JSON-RPC. One endpoint to check balances,
  send, and bond — no heavy SDKs required.
- **Post-quantum** — every signature is **ML-DSA-87** (FIPS 204); hashes are
  **SHA3-256**.
- **Proofs, not trust** — wallets verify balances with Merkle proofs against
  the checkpoint root.
- **Simple ops** — one container, one port. Docker is the production path.

---

## At a glance

| | |
| --- | --- |
| Genesis supply | **19,960,907** SIKKA (1 SIKKA = 10⁹ CHILLAR) |
| Consensus | Checkpoint voting · ≥2/3 bonded stake · round-robin proposer |
| Spam control | Credits (+1/min, cap 100, 1 per tx) |
| Transport | Signed JSON over HTTP |
| Repo | [github.com/sikkalabs/sikka](https://github.com/sikkalabs/sikka) |

---

## Docs

- Run a node: [`docs/docker.md`](docs/docker.md)
- Wallets: [`docs/wallets.md`](docs/wallets.md)
- HTTP + JSON-RPC: [`docs/api.md`](docs/api.md)
