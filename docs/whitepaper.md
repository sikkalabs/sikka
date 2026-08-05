# SIKKA — The Whitepaper

**Version 0.2** · SIKKA chain `sikka` · Genesis supply **19,960,907 SIKKA**

> *sikkā* (Punjabi, from Persian) — the die used for minting coins, and by
> extension the authority to coin money.

SIKKA is a feeless, post-quantum, state-based cryptocurrency designed for
humans, AI agents and micropayments. This document explains *why* it must
exist, *how* it is distributed and paid for, and *exactly* how the network
works, down to the integer arithmetic that mints a CHILLAR.

---

## Contents

1. [The Problem: another coin, but why?](#1-the-problem)
2. [Design Principles](#2-design-principles)
3. [The Unit: SIKKA and CHILLAR](#3-the-unit-sikka-and-chillar)
4. [Supply and Distribution](#4-supply-and-distribution)
5. [The 80% Public Allocation: ERC-20 + Vesting](#5-the-80-public-allocation-erc-20--vesting)
6. [The 20% Faucet Allocation](#6-the-20-faucet-allocation)
7. [Inflation: 1.5%/year, forever, in integer arithmetic](#7-inflation)
8. [The Ledger: State, Not History](#8-the-ledger-state-not-history)
9. [Transactions](#9-transactions)
10. [Anti-Spam Battery](#10-anti-spam-battery)
11. [Cryptography](#11-cryptography)
12. [Consensus: Checkpoint Voting](#12-consensus-checkpoint-voting)
13. [Storage](#13-storage)
14. [Networking](#14-networking)
15. [Fast-Sync and Stateless Wallets](#15-fast-sync-and-stateless-wallets)
16. [Threat Model](#16-threat-model)
17. [Comparison](#17-comparison)
18. [Pseudocode Appendix](#18-pseudocode-appendix)
19. [Glossary](#19-glossary)
20. [References](#20-references)

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
| Big SDKs, contracts, gas | **One JSON-RPC endpoint**, 3 transaction kinds, no gas |
| Storage grows with usage | **Storage grows with accounts only** |
| Micropayments uneconomic | **Feeless + regenerating battery** = per-unit pricing viable |

---

## 2. Design Principles

The entire codebase is built on six rules. Every constant, every hash tag and
every function traces back to one of them.

| Principle | Implementation |
| --- | --- |
| **No fees.** | `Transaction` has no fee field; validators are paid by inflation (`crates/common/src/inflation.rs`). |
| **No history.** | `StateStore` keeps 3 tables; `Checkpoint` commits the state root; transactions are discarded (`crates/state/src/store.rs`). |
| **Private by default.** | Absence of a permanent ledger; payments cannot be reconstructed (`crates/state/src/ledger.rs`). |
| **Post-quantum.** | Every signature ML-DSA-87; every hash SHA3-256; no ECDSA/Ed25519 in the tree (`crates/crypto/src/lib.rs`). |
| **Proofs, not trust.** | SMT inclusion/absence proofs against a signed checkpoint (`crates/wallet/src/proof.rs`). |
| **Determinism above all.** | Integer-only arithmetic; no floating point in consensus (`crates/common/src/inflation.rs`, `crates/common/src/amount.rs`). |

### 2.1 Architecture at a glance

```
                    ┌──────────────────────────────────────────┐
                    │               USERS / AGENTS              │
                    │  wallet.html   sikka CLI   AI agents      │
                    └──────────────┬───────────────────────────┘
                                   │  POST /api/rpc  (JSON-RPC)
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
        └──────────────────────────────────────┬──────────────────┘
                                               │
        ┌──────────────────────────────────────▼──────────────────┐
        │        redb  (ACID, pure-Rust, 3 tables)                │
        │        accounts │ validators │ meta                     │
        └─────────────────────────────────────────────────────────┘
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

## 4. Supply and Distribution

### 4.1 Total supply

The genesis mints exactly **19,960,907 SIKKA** (`DEFAULT_GENESIS_SUPPLY_SIKKA`
in `crates/common/src/default_genesis.rs`). No other supply exists at height 0,
and nothing can be minted except the deterministic inflation of
[§7](#7-inflation).

```
Supply at genesis:           19,960,907 SIKKA
Split ─────────────────────────────────────────────
  80%  Public purchase (ERC-20, vested)    15,968,726 SIKKA
  20%  Faucet (test the network)            3,992,181 SIKKA
       ─────────────────────────────────────
       100%                                 19,960,907 SIKKA
```

| Share | SIKKA | CHILLAR | Purpose |
| --- | ---: | ---: | --- |
| **80%** | 15,968,726 | 15,968,726,000,000,000 | Bought via the SIKKA ERC-20 token `0xbAB5a2CC8C9Eb4042eEAE289b26B66166cf04a81`, vested and released linearly through `SikkaVesting` at `0xe4A5f67529D40ACfF666303Dd0B6F72A734198B3` |
| **20%** | 3,992,181 | 3,992,181,000,000,000 | Faucet: given away so anyone can test and try the network directly, with zero cost and zero permission |

### 4.2 How it lands on-chain

The on-chain genesis encodes the *operational* structure of those allocations
(`default_genesis.rs`):

| On-chain account | SIKKA | Note |
| --- | ---: | --- |
| Cold treasury (admin) | **19,906,907** | Custodian of the liquid mint — not a validator. Holds the vested + faucet allocations |
| Genesis validator A | 30,000 | 10,000 bonded + 20,000 liquid |
| Genesis validator B | 24,000 | 4,000 bonded + 20,000 liquid |
| **Total** | **19,960,907** | |

```
             genesis supply
        ┌──────────────────────┐
        │       19,960,907     │
        └──────────┬───────────┘
                   │
        ┌──────────▼───────────┐
        │     80% / 20%        │
        └──────────┬───────────┘
        ┌──────────▼───────────┐        ┌─────────────────────────┐
        │  80%  public tranche │        │  20%  faucet tranche    │
        │  ERC-20 token        │        │  free for testing       │
        │  0xbAB5…4a81         │        │  anyone can try the net │
        │        │             │        └─────────────────────────┘
        │        ▼             │
        │  SikkaVesting        │
        │  0xe4A5…8B3          │
        │  1 SIKKA / 4 seconds │
        └──────────────────────┘
```

Bonds are locked *out of* allocations (they do not add to supply —
`GenesisConfig::total_supply` sums only allocations). The 20,000-liquid
genesis validators are for operational security, not distribution.

---

## 5. The 80% Public Allocation: ERC-20 + Vesting

### 5.1 The two contracts

| Contract | Address | Role |
| --- | --- | --- |
| **SIKKA token** (ERC-20) | `0xbAB5a2CC8C9Eb4042eEAE289b26B66166cf04a81` | The purchase instrument. Buyers acquire SIKKA here |
| **SikkaVesting** | `0xe4A5f67529D40ACfF666303Dd0B6F72A734198B3` | Linear time-lock release of the purchased supply into circulation |

### 5.2 SikkaVesting mechanics (verbatim from the contract)

| Constant | Value | Meaning |
| --- | ---: | --- |
| `token` | `0xbAB5a2CC…` | the ERC-20 this contract releases |
| `RELEASE_INTERVAL` | `4` seconds | one release tick |
| `RELEASE_AMOUNT` | `1 × 10⁹` | 1 SIKKA per tick (CHILLAR denomination, 9 decimals) |
| `start` | `block.timestamp` at deployment | the clock starts only once |
| `released` | cumulative CHILLAR paid out | monotonic, never exceeds `owed()` |

The release schedule is a pure function of wall-clock time:

```
  owed(t)      =  max(0, ⌊(t − start) / 4⌋) × 1 SIKKA
  releasable() =  min(owed(now) − released, balanceOf(contract))
  release()    =  transfer(releasable() to beneficiary)
```

### 5.3 The release curve

| Elapsed | SIKKA released | % of 80% tranche | % of total supply |
| --- | ---: | ---: | ---: |
| 1 day | 21,600 | 0.14% | 0.11% |
| 1 month | 648,000 | 4.06% | 3.25% |
| 6 months | 3,888,000 | 24.35% | 19.48% |
| 1 year | 7,884,000 | 49.37% | 39.50% |
| ≈ 2.02 years (≈ 739 days) | **15,968,726** | **100%** | **80%** |

```
 released SIKKA (thousands)
  16,000 ┤                                                     ● 100%
        ┤
  12,000 ┤
        ┤                                          ● ~75%
   8,000 ┤                              ● ~50%
        ┤                   ● ~25%
   4,000 ┤
        ┤        ●
        └──────────────────────────────────────────────────────────►
            0     6      12     18     24   months (1 SIKKA / 4 s)
```

At **1 SIKKA every 4 seconds** the entire 80% tranche — 15,968,726 SIKKA — is
released in ≈ **739 days (~2.02 years)**, a constant drip that smooths the
token into circulation and prevents any single-epoch dump.

### 5.4 Safety rails on the contract

| Mechanism | What it prevents |
| --- | --- |
| `nonReentrant` guard | re-entrant `release()` draining the contract |
| `owed()` is monotonic; `released` only increases inside `release()` | double-claiming |
| `release()` requires `amount > 0` | no-op spam |
| `rescueOtherToken()` refuses `token` | cannot exfiltrate the vesting token |
| `updateBeneficiary()` is `onlyBeneficiary` | the deployer cannot be robbed |
| `start` immutable, set at deployment | the schedule cannot be re-anchored later |

---

## 6. The 20% Faucet Allocation

**3,992,181 SIKKA (20% of supply)** are reserved as a faucet so that anyone —
human or agent — can obtain real SIKKA without buying, without KYC and without
waiting for a vesting release. The purpose is direct and deliberate:

- test the network (send, bond, unbond, run a validator) with real stakes;
- build wallets and agents against a live chain;
- bootstrap a distributed holder base rather than a concentrated one;
- let the fee-less, private model be *felt*, not just read about.

| Property | Value |
| --- | --- |
| Tranche | 3,992,181 SIKKA (20% of supply) |
| Mechanism | faucet grants from the cold treasury |
| Recipients | anyone testing the network |
| Cost | zero (no gas exists — see §9) |
| Vesting | none — immediate utility, the point is to use it |

Fresh faucet-funded accounts start with an empty battery (§10) so that even a
free-money mass-funding attack cannot turn into a sybil spam attack.

---

## 7. Inflation

### 7.1 The schedule

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

### 7.2 Integer-only `exp`

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

### 7.3 Projected supply (exact integer math)

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

Values computed by running the protocol's own `checkpoint_inflation` (§7.2)
once per year on the previous year's supply — the same truncating integer
math every validator executes.

The effective yearly dilution of *existing* holders is small and bounded, and
it is the entire cost of running a zero-fee network. No entity can pause,
change or front-run it.

### 7.4 Who gets the inflation

Every checkpoint pays the minted CHILLAR across the **active bonded
validator set, weighted by bond**, with the rounding remainder going to the
proposer. Validators are paid for securing the chain, not for ordering
transactions (ordering is deterministic — see §9.5).

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

## 8. The Ledger: State, Not History

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

### 8.1 Execute → Stage → Commit

Every state change runs through three explicit phases (`Ledger` in
`crates/state/src/ledger.rs`), so a validator can check a proposal *without*
trusting or committing to it:

| Phase | Function | Effect |
| --- | --- | --- |
| **Execute** | `Ledger::execute` | run txs against a read-only overlay; report what *would* change |
| **Stage** | `Ledger::stage` | fold changes into the SMTs, return the new roots, keep an undo log |
| **Commit** | `Ledger::commit` | persist only if roots match the signed checkpoint; else `rollback` |

---

## 9. Transactions

### 9.1 Three kinds, no fee field

| Kind | Tag | Purpose | `to` | `amount` |
| --- | ---: | --- | --- | --- |
| `transfer` | 0 | move CHILLAR | recipient | > 0 |
| `bond` | 1 | lock stake, become a validator | zero | > 0 |
| `unbond` | 2 | start the 7-day cooldown | zero | 0 |

The `Transaction` struct has **no gas field**. Validators are paid by protocol
inflation; spam is bounded by per-account battery (§10) instead of price.

### 9.2 The signed payload

```
signing_bytes =  "SIKKA/tx/v3"
              ‖  str(chain_id)          // u32le length + utf-8
              ‖  kind_tag               // 0 | 1 | 2
              ‖  from ‖ to              // 32 bytes each
              ‖  amount ‖ nonce ‖ timestamp   // u64le each
              ‖  public_key             // 2592 bytes ML-DSA-87
```

The `chain_id` is bound into the signature and the transaction id, so a
transaction signed for one chain can never be replayed on another that shares
keys. The `public_key` is carried explicitly (the ledger stores only the
32-byte address) and the protocol checks it hashes to `from` — a proposer
cannot swap a different key onto a cached id to skip verification.

### 9.3 Transaction id

```
id = SHA3-256("SIKKA/tx-id/v2" ‖ signing_bytes)
```

The signature itself is excluded, so re-signing the same payload (ML-DSA is
randomised by default) yields the same id and cannot enter the mempool twice.

### 9.4 Validation

```
function validate(tx, now):
    check_static(tx, now)       // shape rules + |timestamp−now| ≤ 300 s
    verify_signature(tx)        // ML-DSA-87, context "SIKKA-v1"
    check_chain_id(tx)          // tx.chain_id == ledger.chain_id
```

### 9.5 Canonical ordering — nobody can front-run

Inside a checkpoint, transactions are sorted by a pure function of their
content, **never by arrival time**:

```
order_key(tx) = (tx.from, tx.nonce, tx.id())
```

Because the proposer cannot choose the order, it cannot reorder, front-run or
selectively censor. Every validator replays the identical list and gets the
identical root, or refuses to sign.

### 9.6 Atomic execution rules

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

## 10. Anti-Spam Battery

Fee-less chains must stop free spam by a different mechanism. SIKKA gives each
account a **battery** — a rate limiter, not a price.

| Constant | Value |
| --- | ---: |
| `MAX_BATTERY` | 100 |
| `BATTERY_REGEN_SECS` | 60 s |
| `BATTERY_COST_PER_TX` | 1 |

```
battery_at(now) = min(100, battery + ⌊(now − last_regen_time)/60⌋)
```

Key properties:

- Regeneration is computed from the **transaction's signed timestamp**, never
  a validator's wall clock — every node settles identically.
- Every confirmed transaction costs exactly 1 battery.
- **Newly funded accounts start at 0 battery**, anchored at funding time, so
  an attacker who mints/funds fresh addresses cannot immediately spam.
- A full battery allows 100 transactions; one battery per minute sustains
  1 tx/min forever — comfortable for real use, painful for spam.

```
  battery
    100 ┤●───────────────────────────────   cap
       │ ·
       │   ·
       │     ·          +1 per 60s
    50 ┤        · ·
       │            · · ·
     0 ┤──────────────────────────────► time
```

---

## 11. Cryptography

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

### 11.1 The quantum threat to existing chains

```
      Pre-quantum (ECDSA/Ed25519)              Post-quantum (SIKKA)

  Private key recoverable from public key   Private key NOT recoverable
  once a large-enough QC exists.            from public key, even by QC.
  All historical signatures become          Every signature is ML-DSA-87
  forgeable retroactively.                  Cat-5; forgeability remains
                                            ≥ 2²⁵⁶-equivalent.
```

---

## 12. Consensus: Checkpoint Voting

Consensus is deliberately small. It does not order transactions (that is
deterministic), it does not vote on them individually, and it answers exactly
one question:

> **Does at least two-thirds of the bonded stake agree that this is the state?**

### 12.1 Actors

| Term | Meaning |
| --- | --- |
| Validator | any account that locks a bond (min `supply/100,000` ≈ 200 SIKKA on mainnet) |
| Active set | validators eligible at a height (bonded, not slashed, not unbonding) |
| Bond | stake; the only thing that can be slashed |
| Proposer | round-robin `(height + round) mod active_set` |
| Checkpoint | header (roots, supply, tx_root, round, proposer) + precommit signatures |

### 12.2 The two-phase vote (Tendermint-style, minimal)

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

### 12.3 Liveness without punishment

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

### 12.4 Equivocation evidence

```
Equivocation = two valid, conflicting votes
               from the same validator,
               same height, same round, same kind,
               different checkpoint hashes.
```

Because the two signed votes are self-proving, any node can assemble the
evidence and the next checkpoint burns the bond.

### 12.5 Finality and pruning

- A checkpoint is final when precommit signatures cover ≥2/3 bonded stake.
- Only the **last 100 checkpoints** are retained (`CHECKPOINT_HISTORY`).
- The final state root is the record; the producing transactions are discarded.

---

## 13. Storage

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

### 13.1 Sparse Merkle Tree

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

## 14. Networking

### 14.1 Plain HTTP(S), signed JSON

There is no bespoke wire protocol. Nodes are clients and servers over ordinary
HTTP, so they sit behind any reverse proxy, need no long-lived connections, and
transport encryption is optional — every message carries its own ML-DSA-87
signature over its contents.

| Endpoint | Role |
| --- | --- |
| `POST /api/tx` | submit a transaction |
| `POST /api/tx/sync` | mempool reconciliation |
| `POST /api/vote` | consensus votes |
| `POST /api/checkpoint/proposal` | checkpoint proposal (up to 256 MiB body) |
| `POST /api/checkpoint/finalized` | finalized checkpoint |
| `GET /api/state/snapshot/…` | chunked fast-sync |
| `POST /api/rpc` | JSON-RPC for wallets/CLI/agents |

### 14.2 Mempool sync with Bloom filters

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

## 15. Fast-Sync and Stateless Wallets

### 15.1 Chunked, resumable snapshots

A new or returning node downloads a **snapshot** (finalized checkpoint +
accounts + validators) rather than replaying history — which is impossible
anyway, because history is gone.

- Each chunk ≈ 4 MiB, zstd-compressed, independently hashed.
- Downloads resume after interruption; chunks verify before they are kept.
- The reconstructed state must re-hash to the checkpoint's roots, and total
  supply is re-derived from balances + bonds (a snapshot cannot smuggle coins).

### 15.2 Weak subjectivity

A node accepts an unpinned snapshot only across a **single-height gap**
(`WEAK_SUBJECTIVITY_GAP = 1`). Anything larger requires an operator-pinned
`SIKKA_TRUSTED_CHECKPOINT=<height>:<hash>` — even when the validator root is
unchanged — otherwise a former ≥2/3 set could forge a long-range fork.

### 15.3 Stateless, verifiable wallets

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

---

## 16. Threat Model

| Threat | Defence |
| --- | --- |
| Quantum computer forges signatures | ML-DSA-87 (Cat-5) everywhere; no ECDSA/Ed25519 |
| Transaction spam | per-account battery (+1/min, cap 100, 1/tx); fresh accounts start empty |
| Sybil funding → spam | faucet/target accounts start at 0 battery; genesis accounts start full (cannot be minted) |
| Equivocation / double-signing | the only slashable offence; bond burned on proof |
| Long-range fork | weak-subjectivity gap = 1; `SIKKA_TRUSTED_CHECKPOINT` pin |
| Proposer front-running / reordering | canonical order `(from, nonce, id)`; replay produces identical roots |
| Unsigned-CPU DoS on proposals | proposer signature verified *before* per-tx ML-DSA work |
| Vote flood DoS | votes only tracked ≤ 1 height ahead; ML-DSA verified on arrival |
| Replay across chains | `chain_id` bound into tx/vote/proposal/checkpoint domains |
| Overflow / non-determinism | integer-only arithmetic; `expm1_fixed`; checked adds |
| Mempool memory DoS | capacity caps, eviction of oldest safe runs, nonce-gap purging, 600 s TTL |
| Snapshot smuggling | re-derive supply & roots from the dump; chunk hashes verified |
| History analysis | no transaction ledger exists after finality — nothing to analyse |

---

## 17. Comparison

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
| Fee payer economics | transactor | transactor | transactor | **protocol inflation** |
| Client surface | SDKs, RPC variants | contracts, gas, SDKs | wallet-only | **one JSON-RPC endpoint, 3 tx kinds** |

---

## 18. Pseudocode Appendix

### 18.1 The consensus loop (node)

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

### 18.2 Battery regeneration

```
function battery_at(account, now):
    elapsed_minutes ← (now − account.last_regen_time) / 60
    return min(100, account.battery + elapsed_minutes)
```

### 18.3 Checkpoint inflation (exact integer)

```
function checkpoint_inflation(supply, dt):
    if supply == 0 or dt == 0: return 0
    x ← LN_RATE · dt / SECONDS_PER_YEAR            // LN_RATE = ⌊ln(1.015)·10¹⁸⌋
    factor ← expm1_fixed(x)                        // §7.2, series, truncating
    return supply · factor / 10¹⁸
```

### 18.4 SikkaVesting release

```
function owed(t):
    if t < start: return 0
    return ((t − start) / 4) · 1_000_000_000       // 1 SIKKA per 4 s

function releasable():
    due  ← owed(now)
    return min(due − released, token.balanceOf(this))

function release():
    require releasable() > 0
    released += releasable()
    token.transfer(beneficiary, releasable())      // reentrancy-guarded
```

### 18.5 Account proof verification

```
function verify(proof, root, key, value):
    require len(proof.siblings) ≤ 256
    if proof.leaf == (key, value):
        return fold(key, leaf_hash(key, value)) == root
    return false
```

---

## 19. Glossary

| Term | Definition |
| --- | --- |
| **SIKKA** | the human unit; `1 SIKKA = 10⁹ CHILLAR` |
| **CHILLAR** | the base integer unit of account; the only unit that exists in storage |
| **Battery** | per-account anti-spam allowance, +1/min, cap 100, 1/tx |
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
| **Cold treasury** | the admin address holding the liquid mint (not a validator) |
| **Faucet** | the 20% allocation given away to test the network |

---

## 20. References

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
| [12] | SIKKA ERC-20 — `0xbAB5a2CC8C9Eb4042eEAE289b26B66166cf04a81` |
| [13] | SikkaVesting — `0xe4A5f67529D40ACfF666303Dd0B6F72A734198B3` |
| [14] | Repository — <https://github.com/sikkalabs/sikka> |

---

*End of whitepaper v0.2.*
