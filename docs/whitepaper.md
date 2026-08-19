# SIKKA — The Whitepaper

**SIKKA chain `sikka`** · Genesis supply **19,960,907 SIKKA**

> *sikkā* (Punjabi, from Persian) — the die used for minting coins, and by
> extension the authority to coin money.

SIKKA is a feeless, post-quantum, state-based blockchain designed for
humans, AI agents and micropayments. This document explains *why* it must
exist and *exactly* how the network works, down to the integer arithmetic
that mints a CHILLAR.

---

## Contents

1. [The Problem: another coin, but why?](#1-the-problem)
2. [Design Principles](#2-design-principles)
3. [The Unit: SIKKA and CHILLAR](#3-the-unit-sikka-and-chillar)
4. [Genesis](#4-genesis)
5. [Inflation: 1.5%/year, forever, in integer arithmetic](#5-inflation)
6. [The Ledger: State, Not History](#6-the-ledger-state-not-history)
7. [Transactions](#7-transactions)
8. [Anti-Spam Battery](#8-anti-spam-battery)
9. [Cryptography](#9-cryptography)
10. [Consensus: Checkpoint Voting](#10-consensus-checkpoint-voting)
11. [Protocol Invariants](#11-protocol-invariants)
12. [Validator Economics and Attack Cost](#12-validator-economics-and-attack-cost)
13. [Throughput and Performance](#13-throughput-and-performance)
14. [Storage](#14-storage)
15. [Networking](#15-networking)
16. [Fast-Sync and Stateless Wallets](#16-fast-sync-and-stateless-wallets)
17. [Threat Model](#17-threat-model)
18. [Comparison](#18-comparison)
19. [Pseudocode Appendix](#19-pseudocode-appendix)
20. [Glossary](#20-glossary)
21. [References](#21-references)

---

## 1. The Problem

The world is not short of cryptocurrencies. There are thousands of them, and
nearly all of them share the same inherited architecture and the same inherited
costs. The result is that **money on a blockchain is still worse than money in
a wallet** for the majority of everyday transfers.

### 1.1 The five structural problems

| # | Problem | Consequence | Who pays |
| --- | --- | --- | --- |
| 1 | **Fees** | Every transfer costs gas / miner / network fees, often more than the value being moved | Micropayments are impossible; the poor subsidise the chain |
| 2 | **Public history** | Every payment is stored forever and is readable by anyone | No financial privacy; storage grows without bound; surveillance is trivial |
| 3 | **Pre-quantum cryptography** | ECDSA / Ed25519 signatures are broken by a sufficiently large quantum computer | Every historical and future transaction is forgeable; a chain-wide migration crisis |
| 4 | **Complexity** | Smart-contract runtimes, gas metering, heavy SDKs, L2 stacking | Only specialists can build; AI agents and simple scripts cannot participate |
| 5 | **Throughput that only scales by forgetting less** | More users → more history → bigger nodes → fewer operators → centralisation | The network itself |

### 1.2 The micropayment dead-end

Fees make microtransactions structurally impossible on fee-based chains.

```
   send 0.0001 $  →  fee 0.50 $   →  500,000× fee-to-value ratio  ✗
   send 0.01  $  →  fee 0.50 $   →  5,000×   fee-to-value ratio  ✗
   send 1.00  $  →  fee 0.50 $   →  50%      fee-to-value ratio  ✗
```

An economy of machine-to-machine payments (per-view, per-query, per-inference,
per-packet, per-token) needs a fee **of zero**. The only way to keep validators
paid without charging the sender is to pay them from the protocol itself —
deterministic inflation — which is exactly what SIKKA does.

### 1.3 The "privacy via anonymisation" detour

Privacy-focused chains hide *who* paid *whom* but still store **every
transaction forever**, so:

- node storage grows with transaction throughput, forever;
- the anonymity set shrinks as the ledger is analysed;
- the full history is a permanent data asset that can be mined by anyone.

SIKKA takes a more radical route: **the history is deleted by the protocol**.
If no permanent transaction log exists, past payments cannot be reconstructed
from the chain at all — not by a sophisticated analyst, not by a state actor,
not by a quantum computer. Only current balances exist.

### 1.4 Why SIKKA can exist

The availability of many coins is not an argument against a better one — it is
the evidence that the market is being poorly served. SIKKA is deliberately
opposite on every axis that matters:

| Existing chains | SIKKA |
| --- | --- |
| Fees on every transfer | **0% fees forever** — validators paid by inflation |
| Ledger of every payment, kept forever | **State only** — history discarded after finality |
| ECDSA / Ed25519 | **ML-DSA-87 (FIPS 204, NIST Cat-5)** post-quantum signatures |
| Public IPs, DNS, TLS overlays | **Tor-native peer mesh** — a node's network id *is* its onion |
| Big SDKs, contracts, gas | **One JSON-RPC endpoint**, 3 transaction kinds, no gas |
| Storage grows with usage | **Storage grows with accounts only** |
| Micropayments uneconomic | **Feeless + regenerating battery** = per-unit pricing viable |

---

## 2. Design Principles

The entire codebase is built on seven rules. Every constant, every hash tag and
every function traces back to one of them.

| Principle | Implementation |
| --- | --- |
| **No fees.** | `Transaction` has no fee field; validators are paid by inflation (`crates/common/src/inflation.rs`). |
| **No history.** | `StateStore` keeps 3 tables; `Checkpoint` commits the state root; transactions are discarded (`crates/state/src/store.rs`). |
| **Private by default.** | No permanent ledger; peer mesh is Tor-only so nodes never publish an IP (`crates/state/src/ledger.rs`, `crates/onion`). |
| **Tor-native.** | Federation is onion-only. The `.onion` is derived from the node key, not picked at random (`crates/onion/src/lib.rs`). |
| **Post-quantum.** | Every consensus signature ML-DSA-87; every hash SHA3-256; no ECDSA/Ed25519 in the tree (`crates/crypto/src/lib.rs`). |
| **Proofs, not trust.** | SMT inclusion/absence proofs against a signed checkpoint (`crates/wallet/src/proof.rs`). |
| **Determinism above all.** | Integer-only arithmetic; no floating point in consensus (`crates/common/src/inflation.rs`, `crates/common/src/amount.rs`). |

### 2.1 Architecture at a glance

```
                    ┌──────────────────────────────────────────┐
                    │               USERS / AGENTS              │
                    │  wallet.html   sikka CLI   AI agents      │
                    └──────────────┬───────────────────────────┘
                                   │  POST /api/rpc  (JSON-RPC)
                                   │  optional clearnet reverse proxy
                                   ▼
        ┌──────────────────────────────────────────────────────────┐
        │                        NODE  (port 64552)                │
        │  ┌──────────┐  ┌──────────────┐  ┌─────────────────────┐ │
        │  │  HTTP/RPC │  │  MEMPOOL      │  │  CONSENSUS LOOP     │ │
        │  │  handlers │  │  (Bloom sync) │  │  propose/vote/final │ │
        │  └──────────┘  └──────────────┘  └──────────┬──────────┘ │
        │                                             │            │
        │  ┌──────────────────────────────────────────▼─────────┐ │
        │  │ LEDGER: execute → stage → commit                     │ │
        │  │  Smt(accounts)   Smt(validators)   meta             │ │
        │  └────────────────────────────────────┬────────────────┘ │
        └──────────────┬─────────────────────────┬────────────────┘
                       │                         │
        ┌──────────────▼──────────┐   advertise = http://<derived>.onion
        │  redb  (3 tables)       │              │
        │  accounts│validators│meta│   ┌─────────▼────────────────────┐
        └─────────────────────────┘   │  TOR hidden service + SOCKS5h │
                                      │  peer mesh is onion-only      │
                                      └───────────────────────────────┘
```

---

## 3. The Unit: SIKKA and CHILLAR

SIKKA uses two named units.

| Unit | Definition | Role |
| --- | --- | --- |
| **CHILLAR** | the base integer unit, `1` | the *only* unit that exists in storage, on the wire, and in arithmetic |
| **SIKKA** | `1 SIKKA = 10⁹ CHILLAR = 1,000,000,000 CHILLAR` | the human display unit |

`crates/common/src/constants.rs`:

```rust
/// Smallest divisible unit per SIKKA: 1 SIKKA = 10^9 CHILLAR.
pub const CHILLAR_PER_SIKKA: u64 = 1_000_000_000;
```

### 3.1 Why a "floating" integer unit

All balances are **u64 integers of CHILLAR**. Floating-point numbers are
banned from balances by design:

```
  0.1 SIKKA  == 100_000_000 CHILLAR     (exact integer)
  0.1 SIKKA  == 0.1000000000000000055…  (binary float — WRONG)
```

`crates/common/src/amount.rs` states it directly: *"Every internal amount is an
integer count of CHILLAR; SIKKA is presentation only. Floating point never
touches a balance."* Formatting and parsing are pure string ↔ integer
conversions with up to 9 decimals, trimmed of trailing zeros.

```
  format_sikka(1)                 → "0.000000001"
  format_sikka(1_500_000_000)     → "1.5"
  parse_sikka("1.5")              → 1_500_000_000
  parse_sikka("1.0000000001")     → error (more than 9 decimals)
```

The CHILLAR count of the entire genesis supply:

```
19,960,907 SIKKA  =  19,960,907 × 10⁹ CHILLAR  =  19,960,907,000,000,000 CHILLAR
                     └───────────────────────┘
                      fits comfortably in u64 (max ≈ 1.8×10¹⁹)
```

---

## 4. Genesis

### 4.1 Total supply

The genesis mints exactly **19,960,907 SIKKA** (`DEFAULT_GENESIS_SUPPLY_SIKKA`
in `crates/common/src/default_genesis.rs`). No other supply exists at height 0,
and nothing can be minted except the deterministic inflation of
[§5](#5-inflation).

```
Supply at genesis:           19,960,907 SIKKA
```

### 4.2 Bootstrap accounts

The on-chain genesis encodes the accounts that start the network
(`default_genesis.rs`):

| On-chain account | SIKKA | Note |
| --- | ---: | --- |
| Cold treasury (admin) | **19,906,907** | Custodian of the liquid mint — not a validator |
| Genesis validator A | 30,000 | 10,000 bonded + 20,000 liquid |
| Genesis validator B | 24,000 | 4,000 bonded + 20,000 liquid |
| **Total** | **19,960,907** | |

```
              genesis supply
        ┌──────────────────────┐
        │       19,960,907     │
        └──────────┬───────────┘
                   │
     ┌─────────────┼──────────────┐
     ▼             ▼              ▼
  treasury    validator A    validator B
  19,906,907  10k bonded     4k bonded
              20k liquid     20k liquid
```

Each genesis validator's bond is taken from that account's balance — bonds do
not add extra supply. The two genesis validators exist so the network can
produce checkpoints from height 0.

---

## 5. Inflation

### 5.1 The schedule

- **Rate:** 1.5% per year (`ANNUAL_INFLATION_BPS = 150`).
- **Compounding:** continuous (`exp(ln(1.015) · t) − 1`), forever.
- **Cap:** none. Inflation is the fee the sender never pays.
- **Event:** minted at each **checkpoint** in proportion to the *elapsed wall
  time* since the last checkpoint. An idle chain mints nothing; a busy chain
  mints the same annual rate in smaller pieces.

| Parameter | Value |
| --- | --- |
| `SECONDS_PER_YEAR` | 31,536,000 |
| `LN_RATE` = `⌊ln(1.015)·10¹⁸⌋` | 14,888,612,493,750,216 |
| Fixed-point scale | 10¹⁸ |

The minted amount for a checkpoint spanning `dt` seconds is

```
minted = total_supply × ( exp(LN_RATE · dt / year) − 1 )
```

which over exactly one year is precisely `total_supply × 1.5%` (because
`exp(ln(1.015)) = 1.015`).

### 5.2 Integer-only `exp`

Floating point is a consensus bug: `powf` is not bit-identical across CPUs, and
validators must agree on the **last CHILLAR**. SIKKA therefore computes
`eˣ − 1` by summing the Maclaurin series in fixed point with truncating
division (`crates/common/src/inflation.rs`).

```
function expm1_fixed(x):                  // x in units of 1e18
    term ← x
    sum  ← x
    n    ← 2
    while term > 0 and n < 40:            // series in x^n / n!
        term ← term · x / 1e18 / n
        sum  ← sum + term
    return sum                            // slight under-estimate (safe)
```

Truncation means the protocol **never mints more** than the schedule allows —
the safe direction.

### 5.3 Projected supply (exact integer math)

| Year | Total supply (SIKKA) | Minted that year (SIKKA) |
| --- | ---: | ---: |
| 0 | 19,960,907 | — |
| 1 | 20,260,320 | 299,413 |
| 2 | 20,564,225 | 303,904 |
| 3 | 20,872,688 | 308,463 |
| 4 | 21,185,779 | 313,090 |
| 5 | 21,503,565 | 317,786 |
| 10 | 23,165,447 | 342,346 |
| 20 | 26,884,447 | 397,307 |

Values computed by running the protocol's own `checkpoint_inflation` (§5.2)
once per year on the previous year's supply — the same truncating integer
math every validator executes.

The effective yearly dilution of *existing* holders is small and bounded, and
it is the entire cost of running a zero-fee network. No entity can pause,
change or front-run it.

### 5.4 Who gets the inflation

Every checkpoint pays the minted CHILLAR across the **active bonded
validator set, weighted by bond**, with the rounding remainder going to the
proposer. Validators are paid for securing the chain, not for ordering
transactions (ordering is deterministic — see §7.5).

```
function distribute_rewards(amount, validators, proposer):
    total ← Σ bond(v)
    paid  ← 0
    for v in validators:
        share ← amount · bond(v) / total      // integer division
        pay(v, share); paid += share
    pay(proposer, amount − paid)              // remainder; nothing created, nothing lost
```

Rewards are paid to every *still-active* bonded validator at the height — not
only the exact signer subset of the previous certificate — so two valid
certificates for the same header can never fork the next height's state.

---

## 6. The Ledger: State, Not History

This is the design that makes SIKKA *private by default* and *bounded in
storage*.

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│  TRADITIONAL LEDGER         │        │  SIKKA LEDGER               │
│                             │        │                             │
│  tx1: A→B        stored     │        │  A: balance, nonce, battery │
│  tx2: B→C        stored     │        │  B: balance, nonce, battery │
│  tx3: A→D        stored     │        │  C: balance, nonce, battery │
│  tx4: …          stored     │        │  D: balance, nonce, battery │
│  …forever        stored     │        │                             │
│                             │        │  + state_root (SMT)         │
│  size ∝ transfers           │        │  size ∝ accounts only       │
└─────────────────────────────┘        └─────────────────────────────┘
```

The full chain state is exactly:

| Set | Stored record | Leaf |
| --- | --- | --- |
| Accounts | 28-byte `Account` per address | `SHA3-256(tag‖addr‖balance‖nonce‖battery‖last_regen)` |
| Validators | `Validator` per staker | `SHA3-256(tag‖record)` |
| Meta | one `LedgerMeta` record | height, roots, supply, signers |

A transaction that moves value updates two account leaves and nothing else.
When ≥2/3 of bonded stake signs the resulting state root, the transactions
that produced it are **thrown away**.

### 6.1 Execute → Stage → Commit

Every state change runs through three explicit phases (`Ledger` in
`crates/state/src/ledger.rs`), so a validator can check a proposal *without*
trusting or committing to it:

| Phase | Function | Effect |
| --- | --- | --- |
| **Execute** | `Ledger::execute` | run txs against a read-only overlay; report what *would* change |
| **Stage** | `Ledger::stage` | fold changes into the SMTs, return the new roots, keep an undo log |
| **Commit** | `Ledger::commit` | persist only if roots match the signed checkpoint; else `rollback` |

---

## 7. Transactions

### 7.1 Three kinds, no fee field

| Kind | Tag | Purpose | `to` | `amount` |
| --- | ---: | --- | --- | --- |
| `transfer` | 0 | move CHILLAR | recipient | > 0 |
| `bond` | 1 | lock stake, become a validator | zero | > 0 |
| `unbond` | 2 | start the 7-day cooldown | zero | 0 |

The `Transaction` struct has **no gas field**. Validators are paid by protocol
inflation; spam is bounded by per-account battery (§8) instead of price.

### 7.2 The signed payload

```
signing_bytes =  "SIKKA/tx/v1"
              ‖  str(chain_id)          // u32le length + utf-8
              ‖  genesis_fingerprint    // 32 bytes
              ‖  kind_tag               // 0 | 1 | 2
              ‖  from ‖ to              // 32 bytes each
              ‖  amount ‖ nonce ‖ timestamp   // u64le each
              ‖  public_key             // 2592 bytes ML-DSA-87
```

The `chain_id` and genesis fingerprint are bound into the signature and the
transaction id, so a transaction signed for one network can never be replayed
on another that shares keys or only the same human-readable chain name. The
`public_key` is carried explicitly (the ledger stores only the 32-byte address)
and the protocol checks it hashes to `from` — a proposer cannot swap a
different key onto a cached id to skip verification.

### 7.3 Transaction id

```
id = SHA3-256("SIKKA/tx-id/v1" ‖ signing_bytes)
```

The signature itself is excluded, so re-signing the same payload (ML-DSA is
randomised by default) yields the same id and cannot enter the mempool twice.

### 7.4 Validation

```
function validate(tx, now):
    check_static(tx, now)                 // shape rules + |timestamp−now| ≤ 300 s
    verify_signature(tx)                  // ML-DSA-87, context "SIKKA-v1"
    check_chain_id(tx)                    // tx.chain_id == ledger.chain_id
    check_genesis_fingerprint(tx)         // tx.genesis_fingerprint == ledger fingerprint
```

### 7.5 Canonical ordering — nobody can front-run

Inside a checkpoint, transactions are sorted by a pure function of their
content, **never by arrival time**:

```
order_key(tx) = (tx.from, tx.nonce, tx.id())
```

Because the proposer cannot choose the order, it cannot reorder, front-run or
selectively censor. Every validator replays the identical list and gets the
identical root, or refuses to sign.

### 7.6 Atomic execution rules

```
function apply_transaction(state, tx, context, supply):
    tx.check_static(context.timestamp)            // checkpoint time is THE clock
    sender ← state[tx.from]  or  fail
    require sender.nonce == tx.nonce
    sender.settle_battery(tx.timestamp)
    require sender.battery ≥ 1
    case tx.kind:
      transfer: require balance ≥ amount; balance −= amount; credit(to, amount)
      bond:     require balance ≥ amount; balance −= amount
                require new_bond ≥ min_bond(supply)   // supply/100000
                upsert validator (active next height)
      unbond:   validator.unbonding_since ← tx.timestamp
    sender.nonce += 1
    sender.battery −= 1
```

---

## 8. Anti-Spam Battery

Fee-less chains must stop free spam by a different mechanism. SIKKA gives each
account a **battery** — a rate limiter, not a price.

| Constant | Value |
| --- | ---: |
| `MAX_BATTERY` | 10 |
| `BATTERY_REGEN_SECS` | 60 s |
| `BATTERY_COST_PER_TX` | 1 |

```
battery_at(now) = min(10, battery + ⌊(now − last_regen_time)/60⌋)
```

Key properties:

- Regeneration is computed from the **transaction's signed timestamp**, never
  a validator's wall clock — every node settles identically.
- Every confirmed transaction costs exactly 1 battery.
- **Newly funded accounts start at 0 battery**, anchored at funding time, so
  an attacker who mints/funds fresh addresses cannot immediately spam.
- A full battery allows 10 transactions; one battery per minute sustains
  1 tx/min forever — comfortable for real use, painful for spam.

```
  battery
     10 ┤●───────────────────────────────   cap
       │ ·
       │   ·
       │     ·          +1 per 60s
      5 ┤        · ·
       │            · · ·
      0 ┤──────────────────────────────► time
```

---

## 9. Cryptography

Two primitives, nothing else (`crates/crypto/src/lib.rs`):

| Primitive | Standard | Size | Used for |
| --- | --- | --- | --- |
| **ML-DSA-87** | FIPS 204, NIST security category 5 | PK 2592 B · SK 4896 B · SIG 4627 B | every signature: transactions, votes, proposals, peer announcements |
| **SHA3-256** | FIPS 202 | 32 B | addresses, ids, Merkle nodes, commitments |

Classical signature schemes (ECDSA, Ed25519) are **deliberately absent** —
they are broken by a sufficiently large quantum computer.

```
address = SHA3-256(public_key)          // 32 bytes, 0x-hex on the wire
```

ML-DSA is used with a native context string, `"SIKKA-v1"`, which domain-
separates every signature so one message kind cannot be replayed as another.

### 9.1 The quantum threat to existing chains

```
      Pre-quantum (ECDSA/Ed25519)              Post-quantum (SIKKA)

  Private key recoverable from public key   Private key NOT recoverable
  once a large-enough QC exists.            from public key, even by QC.
  All historical signatures become          Every signature is ML-DSA-87
  forgeable retroactively.                  Cat-5; forgeability remains
                                            ≥ 2²⁵⁶-equivalent.
```

---

## 10. Consensus: Checkpoint Voting

Consensus is deliberately small. It does not order transactions (that is
deterministic), it does not vote on them individually, and it answers exactly
one question:

> **Does at least two-thirds of the bonded stake agree that this is the state?**

### 10.1 Actors

| Term | Meaning |
| --- | --- |
| Validator | any account that locks a bond (min `supply/100,000` ≈ 200 SIKKA on mainnet) |
| Active set | validators eligible at a height (bonded, not slashed, not unbonding) |
| Bond | stake; the only thing that can be slashed |
| Proposer | round-robin `(height + round) mod active_set` |
| Checkpoint | header (roots, supply, tx_root, round, proposer) + precommit signatures |

### 10.2 The two-phase vote (Tendermint-style, minimal)

| Step | Rule |
| --- | --- |
| **Prevote** | soft preference for a checkpoint hash in a round; different rounds may prevote different hashes without equivocation |
| **Precommit** | cast only after ≥2/3 *bonded stake* has prevoted the same hash in that round; precommits are what finalize, and lock the validator for the height |

Quorum is stake-weighted: `ceil(⅔ × total_active_bond)`.

```
    proposer                       validators
       │  proposal (state root + txs)  │
       │──────────────────────────────▶│  replay & compare roots
       │◀──────────────────────────────│  prevote (if roots match)
       │◀────────────┬─────────────────│  ≥⅔ stake prevoted → precommit
       │             │                 │
       │◀────────────┴─────────────────│  precommit signatures
       │══════════════════════════════▶│  finalize, discard txs
```

### 10.3 Liveness without punishment

- Round-robin proposer with a **10-second timeout**; each round hands the turn
  to the next validator in line (`round_at` is a pure function of two agreed
  timestamps).
- Later rounds **adopt** a known open proposal rather than inventing a rival —
  inventing rivals is what deadlocks a 2-of-3 committee when one validator is
  offline.
- **Being offline never burns stake.** Only *equivocation* (two different
  signatures for the same `(height, round, kind)`) is slashable.
- Repeated full-batch proposer misses (default 100, configurable) start a
  **normal unbonding cooldown** — stake is returned, not burned.

### 10.4 Equivocation evidence

```
Equivocation = two valid, conflicting votes
               from the same validator,
               same height, same round, same kind,
               different checkpoint hashes.
```

Because the two signed votes are self-proving, any node can assemble the
evidence and the next checkpoint burns the bond.

### 10.5 Finality and pruning

- A checkpoint is final when precommit signatures cover ≥2/3 bonded stake.
- Only the **last 100 checkpoints** are retained (`CHECKPOINT_HISTORY`).
- The final state root is the record; the producing transactions are discarded.

---

## 11. Protocol Invariants

Everything in this document reduces to a small set of rules the network never
violates. They are worth stating once, together, because every other section is
machinery for enforcing them — and because the codebase can be audited against
them directly.

| # | Invariant | Enforcement |
| --- | --- | --- |
| **I1** | **CHILLAR conservation.** Supply changes by exactly two events: deterministic inflation mints it (up), slashing burns it (down). No transaction creates or destroys value: `Σ balances + Σ bonds == total_supply` at every height | `Ledger::audit_supply` self-check; `distribute_rewards` pays the rounding remainder to the proposer so nothing is lost; snapshots re-derive supply from balances + bonds on restore (`crates/state/src/ledger.rs`) |
| **I2** | **Nonce is a strict counter.** A transaction is rejected unless `tx.nonce == account.nonce`, and every applied transaction increments the nonce by exactly one. Double-spends and replays are structurally impossible | `apply_transaction` (`crates/state/src/ledger.rs:758`) |
| **I3** | **Battery is a pure function.** Charge is computed only from the transaction's *signed timestamp*, never a validator's wall clock, so every node settles the same number. Battery never goes negative and never moves backwards | `Account::settle_battery` / `battery_at` (`crates/common/src/account.rs:44`) |
| **I4** | **Canonical ordering.** Transactions inside a checkpoint are sorted by `(from, nonce, id)` — a pure function of content. Replay is byte-identical, so a proposer cannot reorder, front-run or selectively censor | canonical sort in `build_proposal`; identical roots follow |
| **I5** | **⅔ finality.** A checkpoint is final iff precommit signatures cover ≥ `ceil(⅔ × total_active_bond)`. There is no "two-thirds-ish"; a header can only become final once | `quorum_bond` (`crates/common/src/constants.rs:107`) |
| **I6** | **Deterministic inflation.** The mint is a closed-form function of `(supply, elapsed)` evaluated in integer arithmetic, truncating, so it never exceeds the schedule and is bit-identical on every node | `checkpoint_inflation` (`crates/common/src/inflation.rs:49`) |
| **I7** | **Slashing only on equivocation.** No other action ever burns stake. Being offline costs nothing; only two conflicting signatures at the same `(height, round, kind)` are punishable, and the evidence is self-proving | `crates/consensus/src/equivocation.rs` |
| **I8** | **Bond in, bond out.** Stake is locked from balance by `bond`, returned only by `unbond` plus the 7-day cooldown, and remains slashable for the whole window. No validator can exit before its liabilities are settled | `UNBONDING_SECS` (`crates/common/src/constants.rs:41`) |

Every invariant is enforced in **three independent places**:

```
 1. ADMISSION   would_apply()       →  rejects at the mempool edge what cannot apply
 2. EXECUTION   apply_transaction() →  applies the same rules, again, inside a checkpoint
 3. RESTORE     audit_supply() + re-hash →  rejects a forged or partial snapshot
```

A node that breaks one rule is caught by the other two. A bug becomes a
visible fork, not silent divergence: two honest validators either compute the
same roots (I1–I4, I6) or refuse to sign (I5, I7, I8).

---

## 12. Validator Economics and Attack Cost

### 12.1 The validator's yield

Inflation mints exactly 1.5% of supply per year and pays it to the active
validator set weighted by bond. A validator's return on its *own* bond is
therefore:

```
yield_on_bond  =  minted / total_bonded  =  1.5% × (supply / bonded)
```

| Bonded stake as % of supply | APY on bond |
| ---: | ---: |
| 100% | 1.5% |
| 50% | 3.0% |
| 33⅓% | 4.5% |
| 10% | 15% |
| 5% | 30% |
| 1% | 150% |

This is a self-balancing market. If little is bonded, yields are high and more
holders stake — which lowers the yield again. The protocol never changes the
rate; only the split moves. And because there is **no delegation** — each
validator stakes its own bond — a holder who wants the yield must run a node,
which is exactly the decentralisation pressure a feeless chain needs. A holder
who does not bond is diluted by the full annual rate. Staking is open to
anyone: the minimum bond is `supply/100,000` (≈ 200 SIKKA on mainnet).

### 12.2 What an attacker must buy

Finality requires precommit signatures over ≥ ⅔ of `total_active_bond`. To
finalise a state honest validators would reject, an attacker must control ≥ ⅔
of the bonded stake — it must buy or already hold **at least twice as much
bonded stake as the honest set**. The forward cost of corrupting the chain is
therefore 2× the honest bond, purchased in the open market.

Two SIKKA-specific consequences:

- **There is no history to rewrite.** Once a checkpoint is final, its state
  root is the record and the producing transactions are gone. "Rewriting the
  past" is not a transaction-level attack; the only target is a *new node's*
  view of the present, which is pinned by weak subjectivity (§16.2).
- **Stake is the only weapon, and it is paid for in SIKKA.** An attacker's ⅔
  stake is locked in the protocol while it attacks; the instant it equivocates,
  the evidence travels inside the very next proposal and the bond is burned.
  Attacking with ⅔ of the stake costs ⅔ of the stake, with certainty.

### 12.3 Why the 7-day unbonding closes the escape hatch

The combination of *only-equivocation-is-slashable* and a *7-day cooldown* is
what keeps the ⅔ bound real:

| Property | Effect |
| --- | --- |
| Equivocation detected in ≤ 1 checkpoint | the slashing evidence rides in the next proposal; there is no delay to flee |
| Bond stays slashable during unbonding | `unbond` does not end liability — `is_slashable()` holds until release |
| 7-day cooldown | a validator cannot unbond, re-bond under a fresh identity and equivocate at lower cost; it cannot dump the bond before slashing lands |
| Offline never burns stake | liveness failures force a *return of* stake (100 missed full-batch turns), never destruction — punishment is reserved for deliberate malice |

### 12.4 The cost of the network, and who pays it

On a fee chain, users pay validators per transaction. SIKKA replaces that with
a fixed 1.5%/yr dilution of all holders — a cost that does **not** scale with
volume:

```
Year-1 network cost (illustrative, at $1/SIKKA):

  SIKKA:       0.3M SIKKA minted  ≈  $300k     paid by holders, fixed
  Fee chain:   1% fee × 1M tx × $10 = $100k    paid by users, scales with volume
               1% fee × 1B tx × $10 = $100M    same chain at 1000× volume
```

For a high-velocity, machine-to-machine economy (per-query, per-inference,
per-packet), a fee chain's cost grows linearly with usage while SIKKA's stays
constant. That is the economic argument for the feeless design: **the protocol
charges its users in inflation, not in per-transaction rent.**

---

## 13. Throughput and Performance

Throughput is governed by two deliberately different mechanisms: the **battery**
limits how fast a single account can push transactions, and the **checkpoint
batch** limits how much is finalised at once. There is no arbitrary "gas" knob.

### 13.1 Sustained throughput scales with active accounts

Battery regenerates at 1 unit per 60 s, costs 1 per transaction, and caps at
100. In steady state an account can therefore send **1 transaction per minute
forever**. The network's sustained rate is the sum over all funded accounts:

```
sustained_rate  =  active_funded_accounts ÷ 60   (transactions/second)
```

| Active funded accounts | Sustained rate | Scale |
| ---: | ---: | --- |
| 1,000 | ≈ 17 tx/s | a small town |
| 10,000 | ≈ 167 tx/s | a city |
| 100,000 | ≈ 1,667 tx/s | a region |
| 600,000 | ≈ 10,000 tx/s | design ceiling |

Throughput is bounded by *the number of real users*, not by CPU or bandwidth —
the anti-spam property doing its job. An attacker with 1,000 fresh addresses
gets ~17 tx/s of influence, no matter how fast its hardware is.

### 13.2 Burst and latency

| Mechanism | Value | Consequence |
| --- | ---: | --- |
| Battery burst | 100 tx per account | fire 100, then recharge (~100 min) |
| Checkpoint batch | 10,000 txs | finality granularity; one full batch ≈ 150 MiB JSON |
| Propose interval | 500 ms | a full pool seals on the next proposer turn |
| Max checkpoint delay | 30 s | quiet-chain seal: tx → finality ≤ ~30 s |
| Vote rounds | prevote + precommit | busy-chain finality ≈ 1–3 s |

```
  quiet chain:  submit ──► pooled ──► idle seal (≤ 30 s) ──► final
  busy chain:   submit ──► pooled ──► next turn (≤ 500 ms) ─► prevote ─► precommit ─► final
```

### 13.3 The real bottlenecks

| Bottleneck | Detail |
| --- | --- |
| **Signature verification** | ML-DSA-87 is the expensive primitive. SIKKA verifies each transaction's signature exactly **once** — at mempool admission or proposal receipt — and deliberately does *not* re-verify inside `execute`, halving the cost of a 10,000-tx batch (`crates/state/src/ledger.rs`). |
| **Batch transfer** | a full checkpoint is ~150 MiB of JSON; at the 300 s bulk timeout that needs ≥ 0.5 MB/s per peer. Slow links simply carry smaller batches (a proposer can only include what it received in time), so the chain coalesces rather than stalls. |
| **Mempool depth** | default 50,000 in-flight transactions, 600 s TTL, nonce-gap purging. Excess is shed at the edge, not queued. |

These are **design ceilings, not measured numbers** — the codebase ships no
public benchmark suite yet. The design guarantees the *shapes*: sustained rate
∝ active accounts, bursts fixed at 10,000 per checkpoint, finality bounded by
the two mechanisms above.

---

## 14. Storage

Pure-Rust `redb` (ACID, zero C/C++ DB dependencies). Exactly **three tables**:

```
  accounts   : address (32 B) → Account   (28 B)
  validators : address (32 B) → Validator
  meta       : "ledger"      → LedgerMeta (1 record)
```

```
  storage ≈ (#accounts × 60 B) + (#validators × 2700 B)
```

A ten-year-old chain with 10M accounts and a one-day-old chain with 10M
accounts are the **same size**. This is the direct consequence of the
state-not-history design.

### 14.1 Sparse Merkle Tree

The state root is a SMT over the 256-bit address space
(`crates/state/src/smt.rs`), engineered for three simultaneous properties:

| Property | Mechanism |
| --- | --- |
| **Canonical** | root depends only on the leaf set, never on insertion order; empty subtrees collapse, single-leaf parents collapse back to the leaf |
| **Cheap updates** | a tx touches 2 accounts → O(log₂ accounts) hashes, not 256 |
| **Provable** | inclusion *and* absence proofs fold to the root |

```
        root = SHA3(tag‖left‖right)
       /                        \
      /                          \
   SHA3(leaf)                SHA3(leaf)      ← accounts
      A=0x0f…                   B=0x3a…         (leaf = SHA3(tag‖addr‖account))
```

Proofs are ~log₂(n) sibling hashes and verify in `O(depth)`:

```
function verify_inclusion(proof, root, key, leaf):
    cur ← leaf_hash(key, leaf)
    for depth ← len(proof.siblings)−1 … 0:
        cur ← key[bit depth]  ?  node_hash(proof.siblings[depth], cur)
                              :  node_hash(cur, proof.siblings[depth])
    return cur == root
```

The SMT also carries the **validator root**, so the set of validators
entitled to vote is itself committed to in the header.

---

## 15. Networking

SIKKA is **Tor-native**, not “Tor as an option.” The peer mesh has no clearnet
path, no DNS names, and no operator-chosen listen address. A node’s network
identity is a Tor v3 onion derived from the same ML-DSA-87 seed that signs
consensus messages — so reinstalling the node with the same key republishes the same
`.onion`. Wallets may reach a node through an optional reverse proxy; peers
never do.

### 15.1 Tor-only peer mesh, signed JSON

There is no bespoke wire protocol. Nodes are clients and servers over ordinary
HTTP. **Peer-to-peer federation is Tor-only:** each node advertises
`http://<56chars>.onion` (hidden-service virtport 80, no port in the name) and
dials peers through SOCKS5h (`127.0.0.1:9050` in the production image).
Application-layer ML-DSA-87 signatures make transport TLS unnecessary — every
transaction, vote, proposal and peer announcement is already signed.

The client **refuses to dial** any host that is not a v3 onion (loopback is
allowed only so unit tests can mesh without Tor). Signed announcements that
carry a clearnet URL are rejected the same way. Optional clearnet reverse
proxies may expose port 64552 for wallets and SDKs; honest nodes never use
those URLs as peer endpoints.

Genesis validators carry **no endpoints** in the genesis file. The two
bootstrap onions are the deterministic addresses of the two genesis keys,
hardcoded in `BOOTSTRAP_NODES` (`crates/common/src/constants.rs`). A joiner
needs only its seed: Tor, the hidden service, and the advertise URL are
derived at boot (`sikka-node --prepare-tor`, then the node process).

| Endpoint | Role |
| --- | --- |
| `POST /api/tx` | submit a transaction |
| `POST /api/tx/sync` | mempool reconciliation |
| `POST /api/vote` | consensus votes |
| `POST /api/checkpoint/proposal` | checkpoint proposal (up to 256 MiB body) |
| `POST /api/checkpoint/finalized` | finalized checkpoint |
| `GET /api/state/snapshot/…` | chunked fast-sync |
| `POST /api/rpc` | JSON-RPC for wallets/CLI/agents |
| `POST /api/peers` | signed peer announcements |

Each node probes its own onion through SOCKS (`tor` status: `checking` → `ok`
or `down`) so an operator knows the hidden service is actually reachable, not
merely configured.

### 15.2 Deterministic onion identity

Tor v3 hidden services are keyed by **ed25519** — that is a Tor requirement,
not a SIKKA consensus key. Consensus, payments and peer announcements stay
ML-DSA-87. The onion key is a **transport companion** derived from the node
secret so that:

```
same ML-DSA seed  →  same ed25519 HS key  →  same .onion  forever
```

Derivation (`crates/onion/src/lib.rs`):

```
ikm    ← SHA3-256( "SIKKA/tor-onion-v3/ikm/v1"  ‖  ml_dsa_secret )
seed   ← HKDF-SHA3-256(ikm, info = "SIKKA/tor-onion-v3/v1")   // 32-byte ed25519 seed
pk     ← ed25519_public(seed)
chk    ← SHA3-256( ".onion checksum" ‖ pk ‖ 0x03 )[0..2]
host   ← base32(pk ‖ chk ‖ 0x03) + ".onion"                  // 56 chars + ".onion"
advertise = "http://" + host                                 // virtport 80
```

The expanded ed25519 secret (SHA-512(seed) with clamping) is written into a
C-Tor HiddenServiceDir (`hs_ed25519_secret_key`, `hs_ed25519_public_key`,
`hostname`) that Arti can also load via its ctor keystore. Tor never generates
a random identity for a SIKKA node: if the files are missing, the node
re-derives them from the keystore. Domain tags keep this material from
colliding with any consensus hash.

A peer *is* an ML-DSA-87 key. The 32-byte account address is
`SHA3-256(public_key)`; the onion is HKDF of the matching secret. Announcements
are signed
(`SIKKA/peer-announce/v1` ‖ chain_id ‖ genesis_fingerprint ‖ endpoint ‖ timestamp)
so a node cannot be told that some other key lives at an attacker’s onion.

### 15.3 Mempool sync with Bloom filters

Peer-to-peer mempool reconciliation uses a **Bloom filter** summarising what a
node already holds; the peer replies only with the txs the filter does not
cover.

| Parameter | Value |
| --- | --- |
| bits per item | 10 |
| probes per hash | 5 (from the tx-id digest — already uniform) |
| expected false-positive rate | ≈ 1% |
| max filter | 512 KiB |

False negatives are impossible (nothing is ever lost); false positives merely
delay a duplicate arrival.

---

## 16. Fast-Sync and Stateless Wallets

### 16.1 Chunked, resumable snapshots

A new or returning node downloads a **snapshot** (finalized checkpoint +
accounts + validators) rather than replaying history — which is impossible
anyway, because history is gone.

- Each chunk ≈ 4 MiB, zstd-compressed, independently hashed.
- Downloads resume after interruption; chunks verify before they are kept.
- The reconstructed state must re-hash to the checkpoint's roots, and total
  supply is re-derived from balances + bonds (a snapshot cannot smuggle coins).

### 16.2 Weak subjectivity

A node accepts an unpinned snapshot only across a **single-height gap**
(`WEAK_SUBJECTIVITY_GAP = 1`). Anything larger requires an operator-pinned
`SIKKA_TRUSTED_CHECKPOINT=<height>:<hash>` — even when the validator root is
unchanged — otherwise a former ≥2/3 set could forge a long-range fork.

### 16.3 Stateless, verifiable wallets

A wallet holds **a key and nothing else** — no chain data, no history, no
cache. It asks any node for a balance and *checks the answer*:

```
verify_account_proof(proof, validators):
    1. proof.state_root == checkpoint.state_root
    2. checkpoint carries ≥⅔ bonded-stake signatures you trust
    3. SMT proof folds to that state_root
    4. the account in the proof is yours
```

A lying node cannot pass all four checks, so a wallet never has to trust the
node it talks to — it can point at any public node safely.

### 16.4 Many receive addresses from one seed

The protocol is account-based: leftovers stay on the sender, so there is no
UTXO “change address.” Anyone can still build a wallet that hands out a fresh
receive address per payment — useful for privacy hygiene and bookkeeping —
without any special chain support.

Idea: keep one **master** 32-byte seed offline, and derive child seeds:

```
child_seed_i = SHA3-256(master ‖ "SIKKA/recv/v1" ‖ u32le(i))
key_i        = ML-DSA-87.keygen(child_seed_i)
address_i    = SHA3-256(public_key_i)
```

Each `i` is an independent SIKKA account (its own balance, nonce, battery).
To restore, walk `i = 0, 1, …` via `account.get` and stop after a gap of unused
accounts (ten in a row is a reasonable default). Spend from whichever child
holds funds; the simple browser wallet (`/wallet.html`) is one-key-only —
multi-receive is left to wallets you write yourself (see `docs/wallets.md`).

---

## 17. Threat Model

| Threat | Defence |
| --- | --- |
| Quantum computer forges signatures | ML-DSA-87 (Cat-5) on every consensus message; Tor HS ed25519 is transport-only and never signs value |
| Transaction spam | per-account battery (+1/min, cap 10, 1/tx); fresh accounts start empty |
| Sybil funding → spam | newly funded accounts start at 0 battery; genesis accounts start full (cannot be minted) |
| Equivocation / double-signing | the only slashable offence; bond burned on proof |
| Long-range fork | weak-subjectivity gap = 1; `SIKKA_TRUSTED_CHECKPOINT` pin |
| Proposer front-running / reordering | canonical order `(from, nonce, id)`; replay produces identical roots |
| Unsigned-CPU DoS on proposals | proposer signature verified *before* per-tx ML-DSA work |
| Vote flood DoS | votes only tracked ≤ 1 height ahead; ML-DSA verified on arrival |
| Replay across chains | `chain_id` + `genesis_fingerprint` bound into tx/vote/proposal/checkpoint domains |
| Overflow / non-determinism | integer-only arithmetic; `expm1_fixed`; checked adds |
| Mempool memory DoS | capacity caps, eviction of oldest safe runs, nonce-gap purging, 600 s TTL |
| Snapshot smuggling | re-derive supply & roots from the dump; chunk hashes verified |
| History analysis | no transaction ledger exists after finality — nothing to analyse |
| IP / ASN surveillance of validators | Tor-only peer mesh; onions derived from the node key; clearnet peer URLs rejected |
| Endpoint hijack (“this key lives at my IP”) | signed peer announcements bind ML-DSA key → onion; unsigned referrals cannot evict |
| Random Tor identity drift | onion is HKDF of the ML-DSA secret — reinstall keeps the same `.onion` |

---

## 18. Comparison

| | Bitcoin | Ethereum | Monero | SIKKA |
| --- | --- | --- | --- | --- |
| Transfer fee | yes | gas | yes | **0 (fixed)** |
| Micropayments | no | no | no | **yes** |
| Permanent public ledger | yes | yes | yes (obfuscated) | **no — state only** |
| Past payments reconstructable | yes | yes | analysis possible | **no — history deleted** |
| Signature scheme | ECDSA | ECDSA | Ed25519 | **ML-DSA-87 (PQ)** |
| Storage growth | ∝ usage | ∝ usage | ∝ usage | **∝ accounts** |
| Wallet trust model | SPV (fraud proofs) | full node / RPC trust | full node | **SMT proofs vs. signed checkpoint** |
| Consensus | PoW | PoS | PoW | **checkpoint voting, ⅔ bonded** |
| Peer transport | clearnet / DNS | clearnet / DNS | optional overlays | **Tor-native; identity = onion** |
| Fee payer economics | transactor | transactor | transactor | **protocol inflation** |
| Client surface | SDKs, RPC variants | contracts, gas, SDKs | wallet-only | **one JSON-RPC endpoint, 3 tx kinds** |

---

## 19. Pseudocode Appendix

### 19.1 The consensus loop (node)

```
loop every PROPOSE_INTERVAL:
    if quorum(finalized) exists: broadcast finalized; continue

    if a precommit becomes possible: cast precommit; gossip; check quorum

    expire stale pending stages

    if an open peer proposal exists: adopt it (never invent a rival)

    if it is our turn AND (pool ≥ 10_000 txs  OR  evidence  OR  idle > 30 s):
        txs ← canonical_order(pool)
        (header, staged) ← execute+stage(ledger, txs, evidence, now)
        if staged.root mismatches peers': nobody signs — proposal dies
        sign proposal; prevote; commit our vote to disk BEFORE broadcasting
        broadcast proposal + prevote
        if prevote reaches ⅔: precommit; check quorum
        if precommits reach ⅔: finalize, discard txs, prune mempool
```

### 19.2 Battery regeneration

```
function battery_at(account, now):
    elapsed_minutes ← (now − account.last_regen_time) / 60
    return min(10, account.battery + elapsed_minutes)
```

### 19.3 Checkpoint inflation (exact integer)

```
function checkpoint_inflation(supply, dt):
    if supply == 0 or dt == 0: return 0
    x ← LN_RATE · dt / SECONDS_PER_YEAR            // LN_RATE = ⌊ln(1.015)·10¹⁸⌋
    factor ← expm1_fixed(x)                        // §5.2, series, truncating
    return supply · factor / 10¹⁸
```

### 19.4 Account proof verification

```
function verify(proof, root, key, value):
    require len(proof.siblings) ≤ 256
    if proof.leaf == (key, value):
        return fold(key, leaf_hash(key, value)) == root
    return false
```

### 19.5 Deterministic Tor v3 onion

```
function onion_identity(ml_dsa_secret):
    ikm  ← SHA3-256("SIKKA/tor-onion-v3/ikm/v1" ‖ ml_dsa_secret)
    seed ← HKDF-SHA3-256(ikm, info="SIKKA/tor-onion-v3/v1")     // 32-byte ed25519 seed
    pk   ← ed25519_public(seed)                                 // transport only
    chk  ← SHA3-256(".onion checksum" ‖ pk ‖ 0x03)[0..2]
    host ← base32(pk ‖ chk ‖ 0x03) + ".onion"
    return "http://" + host                                     // virtport 80
```

The ed25519 key never signs a transaction, vote, proposal or announcement.
Those stay ML-DSA-87. Same secret → same onion on every boot.

---

## 20. Glossary

| Term | Definition |
| --- | --- |
| **SIKKA** | the human unit; `1 SIKKA = 10⁹ CHILLAR` |
| **CHILLAR** | the base integer unit of account; the only unit that exists in storage |
| **Battery** | per-account anti-spam allowance, +1/min, cap 10, 1/tx |
| **Checkpoint** | signed commitment to the full state; the unit of finality |
| **Prevote / Precommit** | the two consensus vote kinds |
| **Quorum** | `ceil(⅔ × total_active_bond)` bonded stake |
| **Equivocation** | two conflicting signatures at the same `(height, round, kind)`; the only slashable offence |
| **Bond** | stake locked for validation; min `supply/100,000` |
| **Unbonding** | 7-day cooldown after `unbond`; stake still slashable until released |
| **State root** | SMT root over all accounts |
| **Validator root** | SMT root over all validators |
| **Snapshot** | finalized checkpoint + state dump, used for fast-sync |
| **Weak subjectivity** | trust anchor needed to sync across >1 height |
| **Cold treasury** | the admin address holding the liquid mint at genesis (not a validator) |
| **Onion identity** | Tor v3 `.onion` derived from the node’s ML-DSA secret via HKDF; transport-only |
| **Peer announce** | signed claim `key → http://….onion`; clearnet endpoints are rejected |

---

## 21. References

| # | Source |
| --- | --- |
| [1] | NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA) |
| [2] | NIST FIPS 202 — SHA-3 Standard (SHA3-256) |
| [3] | SIKKA genesis — `crates/common/src/default_genesis.rs` (`19,960,907 SIKKA`) |
| [4] | SIKKA amounts & units — `crates/common/src/amount.rs`, `constants.rs` |
| [5] | SIKKA inflation — `crates/common/src/inflation.rs` |
| [6] | SIKKA ledger — `crates/state/src/ledger.rs` |
| [7] | SIKKA SMT — `crates/state/src/smt.rs` |
| [8] | SIKKA consensus — `crates/consensus/src/{lib,proposal,votes,equivocation}.rs` |
| [9] | SIKKA storage — `crates/state/src/store.rs` |
| [10] | SIKKA wallet proofs — `crates/wallet/src/proof.rs` |
| [11] | SIKKA API — `docs/api.md` |
| [12] | SIKKA Tor onion identity — `crates/onion/src/lib.rs` |
| [13] | Repository — <https://github.com/sikkalabs/sikka> |

---

*End of whitepaper.*
