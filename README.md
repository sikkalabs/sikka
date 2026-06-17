# ⚡ Sikka

A next-generation digital currency built for humans, autonomous agents, and machine-to-machine payments.

**Feeless • Parallel • Quantum-Safe • Tor-Native**

<p>
  <img src="https://img.shields.io/badge/Fees-0-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/Consensus-DAG-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Security-ML--DSA--87-purple?style=flat-square" />
  <a href="https://hub.docker.com/r/besoeasy/sikka"><img src="https://img.shields.io/docker/pulls/besoeasy/sikka?style=flat-square&logo=docker" /></a>
  <a href="https://discord.gg/HxsRdB2zjb"><img src="https://img.shields.io/badge/Discord-Join%20Us-5865F2?style=flat-square&logo=discord&logoColor=white" /></a>
</p>

## 🐳 Quick start

Sikka is lightweight and efficient. The production Docker image is only **17 MB** and bundles the node, HTTP API, web wallet, and DAG explorer.

**Run a node:**

```bash
docker run -d --restart unless-stopped -p 64552:64552 besoeasy/sikka:latest
```

**Run with options** (persistent data, stable onion identity, and a public label):

```bash
docker run -d --restart unless-stopped \
  -p 64552:64552 \
  -v sikka-data:/home/sikka/data \
  -e nodeprivatekey=your-custom-key \
  -e nodeaddress=sikka1p4ktc4mcwzekfauhw2eeqfx5edeffaqtmcv3qaautjkrh55slgrmswvkjvf \
  -e nodemessage="SIKKA relay node v0.0.31" \
  besoeasy/sikka:latest
```

### Environment variables

| Variable         | Required | Description                                                                                                                                                                                                            |
| ---------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nodeprivatekey` | No       | Stable node identity. Use a 64-character hex seed, or any passphrase (hashed to a seed). Stored under the data volume when unset. Controls your `.onion` hostname across restarts.                                     |
| `nodeaddress`    | No       | **Donation address** — a valid `sikka1…` bech32m address where people can send funds. Shown on the node dashboard and in `GET /v1/status` / `GET /v1/sync/status` as `node_address`. Use a wallet address you control. |
| `nodemessage`    | No       | Short **display** blurb for this node (max 100 characters). Same APIs and dashboard.                                                                                                                                   |

**Defaults when `nodeaddress` / `nodemessage` are omitted:**

| Field                         | Default                                                                                       |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `node_address` in status JSON | Network genesis address (`sikka1pd6hpxxz9664h4h3scf8cazdlan33srrg4myywla382avn75rn0fsr537k6`) |
| `node_message` in status JSON | `SIKKA` + release version (e.g. `SIKKA 0.0.31`)                                               |

**Validation** (invalid values prevent startup):

- `nodeaddress` — must decode as a valid Sikka bech32m address (`sikka1…`, version 1, 32-byte payload). Invalid or malformed addresses are rejected.
- `nodemessage` — ASCII letters, digits, spaces, and periods (`.`) only, at most 100 characters. Example: `SIKKA relay node v0.0.31`. Other punctuation and newlines are rejected (safe for status JSON and the dashboard).

`nodeaddress` is the funding address you publish; `nodemessage` is cosmetic text only. Neither changes genesis, Tor routing, or which keys run the node — set `nodeaddress` to a receive address from your wallet.

## Build Locally

```bash
docker build -t sikka:local . && docker run --rm -p 64552:64552 sikka:local
```

---

## 🧠 Core Philosophy

Traditional blockchains force transactions into sequential blocks, creating bottlenecks, unpredictable fees, and reliance on central miners. **Sikka uses a Directed Acyclic Graph (DAG) where every transaction directly extends the network.**

- **Feeless:** Zero hidden network taxes or gas. Send 50, receive exactly 50.
- **Parallel:** Transactions process simultaneously, entirely bypassing block queues.
- **Quantum-Safe:** Secured exclusively by NIST-standardized ML-DSA-87 signatures.
- **Tor-Native:** Built-in Tor routing. Nodes communicate privately via `.onion` addresses.
- **Spam Resistance:** Instead of fees, each transaction performs dynamic, localized Proof of Work that scales with network congestion.
- **Native Multisig:** Built-in M-of-N threshold signatures directly at the protocol level, avoiding complex or expensive smart contracts.

### 🆚 Sikka vs. Traditional Crypto

| Feature          | ⚡ Sikka                 | ⛓️ Traditional Crypto (BTC/ETH) |
| ---------------- | ------------------------ | ------------------------------- |
| **Architecture** | Parallel DAG (Mesh)      | Sequential Blocks (Chain)       |
| **Fees**         | Zero (Feeless)           | Variable (Gas / Miner Fees)     |
| **Processing**   | Parallel & Instant       | Queued in Mempool               |
| **Cryptography** | Post-Quantum (ML-DSA-87) | Classical (ECDSA)               |
| **Multisig**     | Native Protocol-Level    | Smart Contracts (Costs Gas)     |
| **Networking**   | Private (Tor-Native)     | Public (Clearnet)               |

## 🛠️ Technical Highlights

- **Efficient Syncing:** Sikka uses a single `sync_v1` protocol (sparse "have" anchors + server-computed ancestor closure of the responder's tips) for complete DAG reconciliation between peers via `POST /v1/sync`.
- **Pure Go & Lightweight Architecture:** Written entirely in memory-safe Go (Golang) and backed by `bbolt` (a fast, low-level Key-Value store). Sikka skips heavy SQL databases, allowing the entire node to comfortably run on low-end hardware like a Raspberry Pi.

---

## ⚙️ How It Works

### 1. Transaction DAG

Every transaction (except genesis) references exactly **two parent tips** selected from the current frontier of the DAG:

```
        [genesis]
        /        \
      [A]        [B]
      / \        / \
    [C] [D]   [E] [F]      ← tips (no children yet)
         \   /
          [G]              ← new tx; parents = D, E
```

There are no miners, no block producers, and no mempool queue. Each submitted transaction immediately becomes part of the graph and itself becomes a tip that future transactions can build on.

**Benefits:**

- **No throughput ceiling** — transactions are processed in parallel rather than serialized into blocks.
- **No confirmation delays from congestion** — you don't wait for the next block; your transaction is in the graph immediately.
- **Every transaction contributes** — by referencing two tips, each new tx implicitly votes for and validates existing unconfirmed work.

---

### 2. UTXO Model & Token Supply

Sikka uses an **Unspent Transaction Output (UTXO)** ledger: a transaction consumes existing outputs as inputs and creates new outputs. The balance conservation rule must hold exactly:

```
sum(inputs) = sum(outputs)
```

Any deviation — including attempting to collect a fee — is rejected. This makes "feeless" a hard protocol invariant, not a soft policy.

The smallest unit is the **chillar**:

```
1 SIKKA = 10,000,000,000 chillar  (10^10)
```

The total fixed supply encodes the founder's birthday in ISO 8601 (`YYYYMMDD = 19960907`):

```
TotalSupply = 19,960,907 × 10^10 chillar
            = 199,609,070,000,000,000 chillar
```

This entire supply is pre-issued in a single genesis transaction. There is no inflation, no mining reward, and no emission schedule.

**Benefits:**

- **Predictable supply** — no monetary policy risk; the cap is enforced in code.
- **Exact amounts** — 10 decimal places give sub-cent precision for micro-payments (e.g. machine-to-machine API calls).
- **UTXO parallelism** — independent UTXOs can be spent in parallel without touching shared state.

---

### 3. Proof of Work — Congestion-Adaptive Spam Resistance

Instead of transaction fees, every transaction must solve a **SHA3-256 PoW puzzle** whose difficulty scales with live network load. The required minimum leading zero bits are:

```
required_bits = BaseBits + floor(recent_count / BucketSize) × BucketBits

where:
  BaseBits  = 2
  BucketSize = PowTargetTPS × WindowSeconds = 1 × 60 = 60 txs
  BucketBits = 2
  recent_count = number of txs in the DAG timestamped within the last 60 s
```

**Example at different load levels:**

| recent_count (last 60 s) | congestion_buckets | required_bits | expected hashes |
| ------------------------ | ------------------ | ------------- | --------------- |
| 0 – 59                   | 0                  | 2             | ~4              |
| 60 – 119                 | 1                  | 4             | ~16             |
| 120 – 179                | 2                  | 6             | ~64             |
| 180 – 239                | 3                  | 8             | ~256            |

Each extra congestion bucket multiplies the expected cost by **4×** (`2^BucketBits`), making spam exponentially more expensive under load while keeping the baseline cost negligible for normal users.

#### Anti-Selfish-Mining: Tip Commitment

The PoW puzzle input commits to the **current state of the two parent tips**:

```
pow_input = txID || parent[0].pow_hash || parent[1].pow_hash || nonce
pow_hash  = SHA3-256(pow_input)
```

An attacker who pre-mines a transaction against stale tips will produce `parent_pow_hashes` that no longer match the live DAG. The node rejects such a transaction immediately — wasted work cannot be replayed.

**Benefits:**

- **No fees, ever** — spam costs CPU, not money, eliminating economic barriers for small or automated payments.
- **Self-regulating throughput** — difficulty rises automatically when the network is busy and falls when it's quiet.
- **Selfish mining is futile** — PoW is bound to live tip hashes; you must mine against the current DAG state.

---

### 4. Post-Quantum Signatures: ML-DSA-87

All transaction authorization uses **ML-DSA-87** (Module Lattice Digital Signature Algorithm, NIST FIPS 204, security category 5):

| Property            | Value                                                                |
| ------------------- | -------------------------------------------------------------------- |
| Security assumption | Module Learning With Errors (MLWE) — hard even for quantum computers |
| Public key size     | 2,592 bytes                                                          |
| Signature size      | 4,627 bytes                                                          |
| Security level      | ~256-bit post-quantum, equivalent to AES-256                         |

#### Key Derivation

Keys are derived deterministically from a BIP-39 mnemonic (128–256 bits of entropy):

```
mnemonic  ──BIP-39──▶  bip39_seed (64 bytes)
bip39_seed ──HKDF-SHA3-256 (info="sikka:mldsa87:bip39:v1")──▶  ml_dsa_seed (32 bytes)
ml_dsa_seed ──ML-DSA-87──▶  (public_key, private_key)
```

Hierarchical (HD) derivation for multiple addresses follows the same pattern with an extended info string that encodes `account / branch / index`:

```
info = "sikka:mldsa87:hd:v1" || uint32(account) || uint32(branch) || uint32(index)
child_seed = HKDF-SHA3-256(master_seed, salt=∅, info=info)
```

#### Addresses

A Sikka address is a **bech32m**-encoded commitment to a threshold signing policy:

```
policy_descriptor = "mldsa87:<threshold>:[<pk_0>,<pk_1>,…,<pk_n>]"  (keys sorted, hex-encoded)
address_payload   = SHA3-256( version_byte || policy_descriptor )    (32 bytes)
address           = bech32m_encode("sikka", version=1, address_payload)
```

A single-sig address is the degenerate case of a **1-of-1 threshold policy** — no special treatment in the protocol.

**Benefits:**

- **Quantum-resistant today** — classical ECDSA is broken by Shor's algorithm on a sufficiently large quantum computer; MLWE is not.
- **Native multisig at no extra cost** — M-of-N wallets are first-class addresses, not smart contracts. No gas, no bytecode.
- **Deterministic key recovery** — lose your device, recover everything from the mnemonic.

---

### 5. Transaction Signing Payload

Each input is authorized by an ML-DSA-87 signature over a deterministic binary payload that binds the signature to exactly one input in exactly one transaction spending exactly one UTXO:

```
payload = domain_prefix
        | tx_id          (32 bytes, SHA3-256 of tx body)
        | input_index    (8 bytes, big-endian uint64)
        | spent_txid     (32 bytes)
        | spent_index    (8 bytes, big-endian uint64)
        | spent_value    (8 bytes, big-endian uint64, in chillar)
        | addr_len       (2 bytes, big-endian uint16)
        | spent_address  (N bytes, UTF-8)

domain_prefix = "sikka:v2:txinput"  (16 bytes)
```

The `tx_id` itself is a SHA3-256 hash of the transaction body (parents, input outpoints, outputs, timestamp) — **excluding** witness data and PoW fields, so the signature is computed before PoW mining.

**Benefits:**

- **No cross-context replay** — the domain prefix ensures a Sikka signature cannot be repurposed in a different protocol.
- **No transaction malleability** — the txID excludes mutable witness/PoW fields; the signed payload binds the immutable body.
- **Commit-then-mine ordering** — sign first, mine second; the nonce search does not invalidate signatures.

---

### 6. Conflict Resolution — Probabilistic Finality

Double-spends are **not immediately rejected**. Both transactions are accepted into the DAG and coexist until enough descendants accumulate to settle the race deterministically. The winner is selected by:

```
canonical_spend = argmax over competing txs of:
    cumulative_weight(tx)  =  Σ  2^(pow_bits of tx_i)
                              i ∈ descendants(tx) ∪ {tx}

tie-break: lower tx_id (lexicographic) wins
```

A transaction is **confirmed** once its cumulative weight crosses the threshold:

```
cumulative_weight(tx) ≥ ConfirmationThreshold = 200
```

Weight propagation is capped at `16 × ConfirmationThreshold = 3200` to keep `SubmitTx` O(active frontier) rather than O(DAG size).

Losing spends are retained for a **grace period** before physical deletion:

```
grace_period = 16 × PowCongestionWindowSeconds = 16 × 60 = 960 s ≈ 16 minutes
```

This gives Tor-slow peers time to gossip competing transactions before losers disappear.

**Benefits:**

- **No global lock required** — concurrent submissions that accidentally double-spend resolve by accumulated work, just like competing Bitcoin forks, but at the per-UTXO granularity rather than the whole chain.
- **Deterministic convergence** — every node applies the same `argmax(cumulative_weight)` rule, so all honest nodes converge on the same canonical ledger state without a coordinator.
- **Fast finality in practice** — at base difficulty (2 bits), `200` weight units require ~200 descendants, each taking ~4 hashes. Under normal load this settles in seconds.

---

### 7. Peer Sync

Nodes reconcile the full DAG in **a single round-trip** using the `sync_v1` protocol:

```
Client  ──POST /v1/sync──▶  Server
        { "have": ["txID_a", "txID_b", …] }   ← sparse set of anchor tx IDs the client knows

        ◀──────────────────
        { "txs": [ … ] }   ← server computes ancestor-closure of its tips,
                               subtracts client's "have" set, returns the diff
```

There is no block index, no checkpoint, and no multi-round negotiation. The server's response is exactly the set of transactions the client is missing.

**Benefits:**

- **One round-trip** — vs. Bitcoin's multi-step `getblocks` / `getdata` / `inv` handshake.
- **No fork choice complexity** — the DAG has a single canonical history; there is nothing to "choose".
- **Tor-friendly** — fewer round-trips mean lower latency penalty over high-latency `.onion` connections.

---

## 🛡️ Spam & Attack Resistance

Sikka has no transaction fees, so it uses a layered set of protocol rules to make abuse expensive without charging honest users.

### Proof of Work — the primary spam throttle

Every transaction must find a nonce such that:

```
SHA3-256( tx_body || parent_pow_hashes || nonce )
```

has at least **`required_bits`** leading zero bits. The baseline is 2 bits (~4 hashes on average — negligible for a single payment). Under load the bar rises automatically:

```
required_bits = 2 + floor(recent_tx_count / 60) × 2
```

where `recent_tx_count` is the number of transactions timestamped within the last 60 seconds. Every extra 60 transactions above the target rate adds **2 more bits**, which means **4× more expected hashing work** per bucket:

| Transactions in last 60 s | Required bits | Expected hashes per tx |
| ------------------------- | ------------- | ---------------------- |
| 0 – 59 (normal)           | 2             | ~4                     |
| 60 – 119                  | 4             | ~16                    |
| 120 – 179                 | 6             | ~64                    |
| 180 – 239                 | 8             | ~256                   |
| 240 – 299                 | 10            | ~1,024                 |

An attacker trying to flood the network at 300 tx/min must do **1,024 hashes per transaction** — and each submitted transaction makes the next one more expensive still. Legitimate users sending a payment every few minutes always pay the baseline cost of ~4 hashes.

This is **not a fee** — there is no recipient and no economic barrier for small senders. It is a CPU tax that scales with the attacker's own aggression.

### UTXO Maturity — stops chained transaction floods

Every output must age at least **600 seconds** (measured by the transaction timestamp, which is committed into the PoW hash and cannot be faked more than 5 minutes into the future) before it can be spent.

Without this rule an attacker could rapidly chain transactions — spend → receive → spend → receive — creating thousands of dependent transactions at the cost of a single UTXO. With the maturity rule, each hop resets a 10-minute clock. Chaining 10 hops takes at least **100 minutes** of real wall-clock time, making fast-chain spam impractical.

The genesis payout is exempt; all other outputs require a non-zero `created_at`.

### Tip commitment — PoW cannot be pre-mined

The PoW input commits to the **live PoW hashes of both parent tips** at the moment of mining:

```
pow_input = tx_body || parent[0].pow_hash || parent[1].pow_hash || nonce
```

If the tips change while the attacker is mining (because other transactions were submitted), the committed hashes become stale and the node rejects the work. An attacker cannot build up a stockpile of pre-mined transactions and dump them later — every transaction must be mined against the current live state.

### Payload size caps — prevents memory exhaustion

| Limit                            | Value | Protects                       |
| -------------------------------- | ----- | ------------------------------ |
| POST body (per request)          | 1 MiB | Node RAM                       |
| Peer sync response               | 8 MiB | Syncing node RAM               |
| Inputs per transaction           | 64    | Signature verification time    |
| Outputs per transaction          | 256   | Signature verification time    |
| `have` anchors per sync request  | 64    | Ancestor-closure CPU cost      |
| Addresses per discovery announce | 8     | Tor probe goroutine exhaustion |

### Timestamp bounds — prevents future-dating

A transaction with a timestamp more than **5 minutes** in the future is rejected outright. This bounds how far ahead an attacker can date a transaction to game the maturity clock or the congestion window.

### Relay hop limit — prevents amplification

When a node relays a newly submitted transaction to its peers, a hop counter is attached. Nodes refuse to re-relay a transaction that has already been forwarded **3 times**. With a fanout of 16, this means a single transaction reaches at most 16³ = 4,096 peers before relay stops — bounded amplification regardless of network size.

### Peer table cap — prevents Sybil flooding

The in-memory peer table is capped at **10,000 entries**. An attacker continuously announcing fake peers cannot grow the table without bound; old or low-scoring peers are evicted instead.

---

## 📚 Documentation

- **API Reference**: See `api.md`
