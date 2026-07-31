# SIKKA

Feeless, post-quantum payments. Nodes keep **balances**, not history: consensus
signs the current state root, then throws the transactions away. Storage grows
with accounts, not with every payment ever made.

**Website:** [sikkalabs.com](https://sikkalabs.com/)  
**Repository:** [github.com/sikkalabs/sikka](https://github.com/sikkalabs/sikka)  
**Image:** [`ghcr.io/sikkalabs/sikka`](https://github.com/orgs/sikkalabs/packages)  
**Live node:** [1.sikkalabs.com](https://1.sikkalabs.com/) · [wallet](https://1.sikkalabs.com/wallet.html)

---

## Why it exists

Most chains pay validators with fees and grow forever by storing every transfer.
SIKKA does neither:

- **No fees** — validators earn from fixed **1.5%/year** inflation, paid
  automatically into bonded balances when checkpoints finalize.
- **No history** — once ≥2/3 of bond signs a checkpoint, the txs behind it are
  discarded. Wallets verify balances with Merkle proofs against that checkpoint.
- **Post-quantum** — every signature is **ML-DSA-87** (FIPS 204); hashes are
  **SHA3-256**.
- **Simple ops** — one container, one port, HTTP JSON. Optional Tor SOCKS for
  outbound peers.

---

## At a glance

| | |
| --- | --- |
| Supply | **19,960,907** SIKKA at genesis (1 SIKKA = 10⁹ CHILLAR) |
| Consensus | Checkpoint voting, ≥2/3 bonded stake, round-robin proposer |
| Spam | On-chain credits (+1/min, cap 100, 1 per tx) |
| Transport | Signed JSON over plain HTTP |
| Genesis validator | `0x9949…447`, bonded `min_bond × 100` |

---

## Quick start

Full runbook (join, fund, bond, CLI): **[`docs/docker.md`](docs/docker.md)**.  
Build a wallet: **[`docs/wallets.md`](docs/wallets.md)**.  
HTTP + JSON-RPC: **[`docs/api.md`](docs/api.md)**.

---

## Repository layout

```text
crates/
  crypto      ML-DSA-87, SHA3-256
  common      types, genesis, inflation, codec
  state       Sparse Merkle Tree, ledger, snapshots
  consensus   proposals, votes, equivocation
  checkpoint  finalized checkpoint store
  p2p         peer HTTP, mempool, discovery
  rpc         JSON-RPC types + client
  wallet      keystore, signing, proof verify
  node        binary: state + HTTP + loops
  cli         `sikka` wallet / inspector
public/       landing page + browser wallet
docs/         docker + API guides
```
