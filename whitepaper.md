# Sikka: A Next-Generation Parallel, Feeless, and Quantum-Safe Digital Currency

## 1. Abstract
Sikka is a high-throughput, decentralized state machine designed for autonomous agents, machine-to-machine payments, and human users. It addresses the fundamental limitations of serialized blockchain architectures by utilizing a Directed Acyclic Graph (DAG) combined with an Unspent Transaction Output (UTXO) model. Sikka operates as a purely feeless, parallel-processing, quantum-safe, and Tor-native network. By replacing global synchronization with a localized, adaptive cryptographic puzzle, Sikka limits Sybil attacks and bounds network throughput without transaction fees or smart contract execution costs.

## 2. Executive Summary (TL;DR)
For readers requiring a high-level overview:
- **Zero-Fee Invariant:** The protocol mathematically enforces strict input-output equivalence, precluding the possibility of network fees.
- **Lock-Free Concurrency:** Sikka processes transactions as disjoint state transitions, allowing unbounded parallel execution.
- **Quantum-Resistant Cryptography:** Sikka utilizes NIST-standardized ML-DSA-87 to defend against polynomial-time quantum attacks (e.g., Shor's Algorithm).
- **Default Network Obfuscation:** Node topology and IP routing are secured via an integrated Tor hidden service architecture.
- **Asymptotic Energy Efficiency:** The network secures consensus with $\mathcal{O}(1)$ hashing complexity per node, diverging from the $\mathcal{O}(N)$ energy expenditure of global proof-of-work arrays.
- **Epoch-Based Witness Compaction (EWC):** Old confirmed transactions are permanently deleted at the protocol level. A Merkle Mountain Range commitment allows any node to cryptographically prove a deleted transaction occurred via a compact $\mathcal{O}(\log N)$ inclusion proof, achieving a ~10,000× storage reduction without sacrificing verifiability.

## 3. Structural Limitations of Early Feeless DAGs
The architecture of Sikka derives from the theoretical limits encountered by early feeless DAG structures, notably the block-lattice model:

- **Sybil Vulnerability & Static Hash Puzzles:** Networks relying on static Proof of Work (PoW) exhibit poor fault tolerance under sustained Sybil attacks, resulting in state bloat. Sikka resolves this via an Adaptive Cryptographic Puzzle; the difficulty scalar $D$ increases exponentially relative to the localized temporal congestion.
- **Sequential Bottlenecks:** Block-lattice architectures enforce a single unified chain per account, resulting in sequential state transitions. Sikka's UTXO model permits unbounded parallelism for non-intersecting sets of UTXOs.
- **Lack of Post-Quantum Security:** Reliance on Ed25519 leaves legacy networks vulnerable to quantum decryption. Sikka natively integrates ML-DSA-87.
- **Clearnet Topologies:** Legacy nodes expose IP addresses, risking targeted DDoS attacks and deanonymization. Sikka relies on an implicit overlay routing network (Tor).

## 4. Disjoint State Transitions and Lock-Free Concurrency
Traditional blockchains (and block-lattice models) rely on an Account Model, which enforces strict serialization of state transitions. If a state $S$ is modified by transactions $T_1$ and $T_2$, they must be ordered sequentially to prevent race conditions ($Nonce_{T1} < Nonce_{T2}$).

Sikka adopts an **Unspent Transaction Output (UTXO)** model, fundamentally changing the concurrency paradigm. We define a transaction $T$ as a pure function mapping a set of input UTXOs $I$ to a set of output UTXOs $O$. 

Two transactions $T_1$ and $T_2$ are strictly disjoint and can be executed simultaneously on independent threads if and only if their input read sets do not intersect:
$$ I(T_1) \cap I(T_2) = \emptyset $$

Because each UTXO acts as an independent cryptographic bearer instrument, the node's validation engine does not require global mutex locks. The network achieves horizontal scalability bounded only by the host hardware's parallel processing capacity.

## 5. Core Architecture & Protocol Specification

### 5.1 Directed Acyclic Graph (DAG) Topology
Sikka dispenses with the concept of discrete blocks. The ledger is represented as a strictly directed acyclic graph $G = (V, E)$, where vertices $V$ represent transactions, and directed edges $E$ represent cryptographic parent references. Every newly broadcast transaction $v_{new}$ must append to the frontier of the DAG by referencing exactly two terminal nodes (tips) $\{p_1, p_2\} \subset V$.

```mermaid
graph TD
    A[Genesis Tx] --> B[Tx 1]
    A --> C[Tx 2]
    B --> D[Tx 3]
    C --> D
    B --> E[Tx 4]
    D --> F[New Tip v_new]
    E --> F
```

A valid Sikka vertex (Transaction) requires:
- `Parents`: Two references defining edges in $E$.
- `Inputs` & `Outputs`: Enforcing the zero-sum invariant $\sum_{i \in I} value(i) = \sum_{o \in O} value(o)$.
- `PowNonce` & `PowBits`: The nonce satisfying the hash puzzle.
- `ParentPowHashes`: A commitment to the cryptographic state of $\{p_1, p_2\}$ during mining.

### 5.2 Adaptive Cryptographic Puzzle (Sybil Defense)
To prevent throughput saturation and unbounded graph inflation, Sikka employs an **Adaptive Cryptographic Puzzle**. Rather than a global difficulty adjustment, Sikka computes a localized congestion factor $C(v)$ by traversing the topological ancestors of the proposed transaction $v$ within a temporal window $W$ (e.g., $W = 60$ seconds).

```go
// Algorithm 1: Adaptive Puzzle Difficulty Calculation
function ComputeRequiredBits(tx):
    ancestors = TraverseAncestorsByTime(tx.Parents, window=60_seconds)
    tx_count = length(ancestors)
    
    if tx_count > BASE_THROUGHPUT:
        overflow_buckets = ceil((tx_count - BASE_THROUGHPUT) / BASE_THROUGHPUT)
        // Difficulty doubles for every overflow bucket
        return MIN_BITS + (overflow_buckets * 2)
    else:
        return MIN_BITS
```

As the transaction rate exceeds the designated boundary, the requisite hashing entropy grows exponentially. An adversary attempting to flood the network faces a geometric explosion in required computational cycles, enforcing strict rate-limiting without monetary fees.

### 5.3 Conflict Resolution and Asymptotic Probabilistic Finality
Because Sikka lacks a synchronized block leader, conflicting transactions (double-spends) may be broadcast simultaneously. Sikka guarantees consensus via **Asymptotic Probabilistic Finality**.

Each transaction accumulates a monotonic scalar `weight`, computed by the sum of all descendant vertices referencing it.

```go
// Algorithm 2: Monotonic Weight Propagation
function PropagateWeight(new_tx):
    queue = [new_tx.Parents]
    visited = {}
    
    while queue is not empty:
        node = queue.pop()
        if node not in visited:
            node.weight += 1
            visited.add(node)
            // Ceiling to bound memory complexity
            if node.weight < SATURATION_LIMIT:
                queue.push(node.Parents)
```

For any conflicting pair $\{T_A, T_B\}$ attempting to consume the same input set, nodes deterministically select the branch with the maximum cumulative weight. 
$$ Winner = \arg\max_{T \in \{T_A, T_B\}} Weight(T) $$
If $Weight(T_A) = Weight(T_B)$, a deterministic lexicographical sort of the transaction hashes breaks the symmetry. The probability of a state reversal decays exponentially as weight increases: $P(reversal) \propto e^{-\lambda \cdot W(T)}$.

### 5.4 Quantum-Safe Cryptography (ML-DSA-87)
Sikka achieves post-quantum security guarantees through the exclusive use of ML-DSA-87 (Module Lattice Digital Signature Algorithm). To prevent chosen-ciphertext and cross-context replay attacks, the signing payload involves strict deterministic domain binding.

```go
// Algorithm 3: Domain-Bound Signing Payload Construction
function ConstructPayload(tx, spent_utxo):
    prefix = bytes("sikka:v2:txinput")
    tx_hash = SHA3_256(tx.Body)
    return concat(prefix, tx_hash, spent_utxo.TxID, spent_utxo.Index, spent_utxo.Address)
```

### 5.5 Native Protocol-Level Multisig (M-of-N Thresholds)
Sikka implements $M$-of-$N$ threshold signatures natively without requiring Turing-complete execution environments. 

A multisig address is deterministically derived from a canonical sorted vector of ML-DSA-87 public keys and a scalar threshold $M$:
$$ Address = Bech32m(SHA3\_256(M \parallel PK_0 \parallel PK_1 \dots \parallel PK_N)) $$

Validation requires $\mathcal{O}(N)$ signature checks per input, strictly bounded by protocol constants to prevent resource exhaustion attacks during verification.

### 5.6 Airdrop Distribution & Network Incentives
Sikka maintains a strictly hardcoded maximal supply of $19,960,907 \times 10^{10}$ minimal base units (`chillar`). To bootstrap the network state, $100\%$ of the initial issuance is distributed via an automated, verifiable randomized selection algorithm targeting active full nodes holding the ledger state over the initial $T_0 + 6\ months$ epoch.

**Long-Term Asymptotic Incentives:**
Without transaction fees, network resilience relies on intrinsic, non-monetary utility functions:
1. **Commercial Finality:** Merchants run full nodes to ensure $\mathcal{O}(1)$ latency verification of incoming payments without reliance on third-party RPC relays.
2. **Data Availability:** Application developers require persistent read/write access to the global state matrix.
3. **Byzantine Fault Tolerance:** Privacy and censorship-resistance advocates contribute redundancy to the overlay network.

### 5.7 Integrated Onion Routing and P2P Overlay
Sikka obfuscates the physical IP topology of the network via a tightly coupled Tor daemon. The node deterministically generates an Ed25519 identity key, which mathematically derives a Tor Hidden Service (V3 `.onion` address). 

Nodes communicate via a multiplexed gossip protocol over encrypted Tor circuits. Because all incoming and outgoing connections traverse minimum 3-hop onion routes, the protocol achieves strong network-layer anonymity, making targeted Eclipse and DDoS attacks computationally intractable to execute against specific validators.

### 5.8 Topological Garbage Collection of Orphaned Subgraphs
To ensure the space complexity of the node remains strictly bounded (avoiding "ledger bloat"), Sikka employs active **Topological Garbage Collection**.

Once a conflict resolves and the winning transaction reaches the $SATURATION\_LIMIT$, the losing subgraph becomes mathematically orphaned. A background daemon executes a recursive post-order traversal to identify and safely deallocate these invalid vertices.

```go
// Algorithm 4: Subgraph Deallocation (Garbage Collection)
function PruneOrphanedSubgraph(losing_tx):
    stack = [losing_tx]
    while stack is not empty:
        node = stack.pop()
        for child in node.children:
            stack.push(child)
        Database.Delete(node) // Space Complexity O(1) per node
```
Furthermore, fully consumed historical UTXOs are stripped of their signature payloads, reducing their memory footprint to a minimal cryptographic hash necessary for preserving topological ancestry.

### 5.9 Light Clients & Simplified Sync API
Light clients achieve $SPV$ (Simplified Payment Verification) guarantees by exclusively downloading subgraphs related to their known public keys. By querying the `/v1/sync/tail` endpoint, a light client verifies the cumulative weight of its relevant tips, trusting the probabilistic finality model without storing the global state matrix $V$.

### 5.11 Deep Finality Guard: Witness Stripping
The dominant storage cost of a long-running Sikka node is the ML-DSA-87 signature witness embedded in every transaction — approximately 4,595 bytes per input. This data is strictly necessary at the moment a transaction is first received and validated but is cryptographically inert afterwards: it will never be re-read by any future state transition.

Sikka implements **Witness Stripping** — a protocol-level background process that permanently deletes ML-DSA-87 signature bytes from historical transactions once they have satisfied a **dual-condition Deep Finality Guard**. Both conditions must hold simultaneously; neither alone is sufficient:

$$\text{EligibleToStrip}(T) \iff \text{Age}(T) \ge \tau_{age} \;\land\; W(T) \ge \tau_{weight} \;\land\; \text{AllOutputsSpent}(T)$$

where $\tau_{age} = 180\;\text{days}$ and $\tau_{weight} = 1000$ (five times the confirmation threshold).

```go
// Algorithm 10: Deep Finality Guard (implemented in witness_compaction.go)
const (
    WitnessMinAgeSecs = 180 * 24 * 60 * 60  // 180 days
    WitnessMinWeight  = 1000                 // 5 × confirmationThreshold
)

function CanStripWitness(tx, currentWeight, allOutputsSpent):
    ageSeconds = now() - tx.Timestamp
    return allOutputsSpent           // No future spend can reference this UTXO
        AND ageSeconds >= WitnessMinAgeSecs  // 180-day bootstrap window expired
        AND currentWeight >= WitnessMinWeight // 1000 honest nodes built upon it

function RunWitnessSweep(dag):
    // Runs hourly as a low-priority background goroutine (not on SubmitTx path)
    for tx in dag.AllTransactions():
        if CanStripWitness(tx, dag.Weight(tx.ID), dag.AllOutputsSpent(tx)):
            stripWitnessFromDisk(tx.ID)     // Atomic bbolt write
            tx.WitnessStripped = true       // Syncing nodes interpret absent witness as intentional
```

**Security Rationale for the Dual Guard:**

The time gate ($\tau_{age} = 180\;\text{days}$) ensures a new node bootstrapping the network always has a minimum 6-month window to download and independently verify the full signature history before any evidence is deleted. The weight gate ($\tau_{weight} = 1000$) ensures that 1,000 independent transactions have been mined on top of the stripped transaction — each one submitted by a node that independently ran `verify_mldsa87()` against the live signature at inclusion time. Together, they make the probability of successful history forgery negligible: an attacker would need to sustain a Sybil cluster visible to the honest network for 180 days while accumulating 1,000 weight, which is detectable and computationally expensive.

**What Remains After Stripping:**

| Field | Retained? | Purpose |
|---|---|---|
| `TxID` (SHA3_256 of original body) | ✅ Yes | Unique identity; hash chain integrity |
| `Parents` | ✅ Yes | DAG topology preserved |
| `ParentPowHashes` | ✅ Yes | Selfish-mining defense intact |
| `Outputs` (addresses + values) | ✅ Yes | UTXO lineage provable |
| `PowNonce` / `PowBits` | ✅ Yes | PoW validity re-verifiable |
| `Timestamp` | ✅ Yes | Age computation |
| `WitnessStripped` flag | ✅ Yes (new) | Syncing nodes distinguish absent-by-design from corruption |
| ML-DSA-87 signatures | ❌ Deleted | Signature bytes permanently removed |

**Storage Impact:** At 100 tx/sec sustained over 10 years, witness stripping alone reduces the `txs` bbolt bucket from ~82 GB to ~5 GB — a **~16× reduction** in the dominant storage component, without introducing any new cryptographic subsystems.



### 5.10 Epoch-Based Witness Compaction (EWC)
A fundamental problem for any long-lived DAG is unbounded storage growth. The existing dead-branch pruning (Section 5.8) removes only losing conflict subgraphs. The winning chain of confirmed, fully spent transactions still grows permanently. A node operating for 5+ years accumulates terabytes of transaction bodies that are **cryptographically inert** — they will never be referenced by a future transaction input yet cannot currently be deleted without breaking ancestry proofs.

Sikka solves this at the **protocol level** via Epoch-Based Witness Compaction. At regular epoch boundaries, the network collectively commits to a compact cryptographic digest of all historical transactions. After finalization, the raw transaction bodies are **permanently and irrecoverably deleted** from all nodes. Any node can still prove a deleted transaction occurred by presenting a compact Merkle inclusion proof against the committed digest. This draws from three research bodies: Utreexo's accumulator model (Dryja, MIT, 2019), Grin/Mimblewimble's transaction kernel design, and Merkle Mountain Range (MMR) structures.

#### Epoch Boundaries
The DAG lifetime is partitioned into discrete epochs. An epoch $E_k$ closes every `EPOCH_SIZE = 10,000` confirmed transactions.

```go
// Algorithm 5: Epoch Boundary Detection
function IsEpochBoundary(dag):
    confirmed_count = CountConfirmedTransactions(dag)
    return confirmed_count > 0 AND confirmed_count % EPOCH_SIZE == 0
```

#### Transaction Kernels & the Epoch Witness Root
When an epoch closes, every node independently computes an **Epoch Witness Root** by building a Merkle Mountain Range (MMR) over compact **Transaction Kernels** — the minimal irreducible fingerprint of each transaction, containing only cryptographic hashes and metadata. Crucially, signatures, full addresses, and numeric values are **not included** in the kernel; they were verified at inclusion time and are no longer needed for proof-of-existence.

```go
// TransactionKernel: Minimal persistent record of a confirmed transaction
TransactionKernel {
    TxID:         SHA3_256(full_tx_body)        // Unique identity commitment
    InputHashes:  [SHA3_256(utxo_ref), ...]     // UTXOs consumed (hashed)
    OutputHashes: [SHA3_256(new_output), ...]   // UTXOs created (hashed)
    PowBits:      uint32                        // Difficulty satisfied
    Timestamp:    int64                         // Unix epoch
    // Signatures, addresses, and values are intentionally excluded
}

// Algorithm 6: Epoch Witness Root Construction
function BuildEpochWitnessRoot(epoch_txns):
    mmr = NewMerkleMMR()
    sorted_txns = TopologicalSort(epoch_txns)   // Deterministic ordering
    for tx in sorted_txns:
        kernel = TransactionKernel{
            TxID:         SHA3_256(tx.Body),
            InputHashes:  [SHA3_256(u) for u in tx.Inputs],
            OutputHashes: [SHA3_256(o) for o in tx.Outputs],
            PowBits:      tx.PowBits,
            Timestamp:    tx.Timestamp,
        }
        mmr.Append(SHA3_256(kernel))
    return mmr.Root()  // Single 32-byte commitment over entire epoch
```

Because `TopologicalSort` is deterministic given the same DAG state, all honest nodes independently compute an **identical** 32-byte `EpochWitnessRoot` for the same epoch.

#### Epoch Seal Transaction
The `EpochWitnessRoot` is published into the DAG via a protocol-reserved **Epoch Seal Transaction**. This is a zero-value vertex participating in the standard DAG weight accumulation process. Nodes independently validate each received seal by recomputing the witness root and rejecting any seal with a mismatching digest — a dishonest seal can never accumulate the weight required for finalization.

```go
// EpochSealTransaction: Protocol-reserved DAG vertex
EpochSealTransaction {
    Type:           EPOCH_SEAL       // Protocol-reserved type identifier
    EpochNumber:    uint64
    EpochStartTxID: [32]byte        // First confirmed tx of this epoch
    EpochEndTxID:   [32]byte        // Last confirmed tx of this epoch
    WitnessRoot:    [32]byte        // MMR root from Algorithm 6
    TxCount:        uint64          // Omission-attack prevention
    Parents:        [2][32]byte     // Standard DAG parent references
    PowNonce:       uint64          // Must satisfy current adaptive PoW
}

// Algorithm 7: Epoch Seal Validation (executed by every receiving node)
function ValidateEpochSeal(seal, dag):
    epoch_txns = GetTransactionsInRange(dag, seal.EpochStartTxID, seal.EpochEndTxID)

    // Reject if the node's independent calculation disagrees
    expected_root = BuildEpochWitnessRoot(epoch_txns)
    if seal.WitnessRoot != expected_root:
        return REJECT

    // Reject if tx count does not match (prevents selective omission)
    if len(epoch_txns) != seal.TxCount:
        return REJECT

    return ACCEPT
```

#### Compaction Engine: Permanent Deletion
Once an Epoch Seal reaches finality (`weight >= CONFIRMATION_THRESHOLD`) and a grace period of `COMPACTION_GRACE_EPOCHS = 2` epochs elapses — ensuring network-wide synchronization — the **Compaction Engine** runs. It replaces every full transaction body in the epoch with a 96-byte `TombstoneRecord`, permanently freeing the disk space.

```go
// TombstoneRecord: Replaces a full tx after compaction (96 bytes)
TombstoneRecord {
    TxID:        [32]byte   // SHA3_256 of original tx body
    EpochSealID: [32]byte   // TxID of the containing finalized Epoch Seal
    MMRIndex:    uint32     // Leaf position in the MMR for proof path lookup
}

// Algorithm 8: Epoch Compaction (Permanent Data Deletion)
function RunCompactionEngine(dag, finalized_seal):
    epoch_txns = GetTransactionsInRange(dag, finalized_seal.EpochStartTxID,
                                             finalized_seal.EpochEndTxID)
    for tx in epoch_txns:
        tombstone = TombstoneRecord{
            TxID:        SHA3_256(tx.Body),
            EpochSealID: finalized_seal.TxID,
            MMRIndex:    tx.MMRLeafIndex,
        }
        dag.ReplaceFull(tx, tombstone)
        // Original tx body (signatures, witnesses, addresses, values)
        // is now permanently deleted. Space Complexity: O(1) per tx.
```

#### Historical Inclusion Proof: Proving a Deleted Transaction Occurred
A sender wishing to prove a compacted transaction existed presents a **Historical Inclusion Proof** — a `TransactionKernel` plus a $\mathcal{O}(\log N)$ Merkle sibling path. Verification requires only the 32-byte `WitnessRoot` stored permanently in the Epoch Seal; no historical transaction data is needed.

```go
// HistoricalInclusionProof: Proves a deleted tx existed and was valid
HistoricalInclusionProof {
    TxID:          [32]byte           // Identity of the deleted transaction
    Kernel:        TransactionKernel  // Minimal preserved fingerprint
    MMRProof:      []byte             // Merkle sibling path, O(log N) size
    EpochSealTxID: [32]byte           // Finalized Epoch Seal anchoring the proof
}

// Algorithm 9: Historical Inclusion Proof Verification
function VerifyHistoricalInclusion(proof, dag):
    // Step 1: Retrieve the finalized Epoch Seal header (always retained)
    seal = dag.GetEpochSeal(proof.EpochSealTxID)
    if seal.Weight < CONFIRMATION_THRESHOLD:
        return REJECT  // Seal not yet finalized

    // Step 2: Recompute leaf hash from the presented kernel
    leaf_hash = SHA3_256(proof.Kernel)

    // Step 3: Verify Merkle path resolves to the committed WitnessRoot
    computed_root = MMR.VerifyInclusionPath(leaf_hash, proof.MMRProof)
    if computed_root != seal.WitnessRoot:
        return REJECT  // Proof invalid or forged

    // Step 4: Ensure the proof identity matches the kernel
    if proof.TxID != proof.Kernel.TxID:
        return REJECT

    return ACCEPT  // Transaction provably existed and was valid
```

#### Storage Complexity After Full Compaction

The following table shows what a fully-compacted Sikka node retains and its asymptotic storage profile at sustained load:

| Data Class | Per-Unit Size | Retention Policy |
|---|---|---|
| **Live DAG Tips** | ~5 KB | Retained until confirmed |
| **Unspent UTXO Set** | ~100 bytes | Retained until spent |
| **Epoch Seal Transactions** | ~200 bytes | Retained **permanently** |
| **Tombstone Records** | 96 bytes | Retained **permanently** in place of deleted txns |
| **Full Tx Bodies** | ~5 KB | **Deleted** after grace period |

At 100 tx/sec sustained over 10 years, the naive uncompacted history would reach ~**15 TB**. With EWC active, the compacted node retains approximately **1.5 GB** (tombstones + seals) — a **~10,000× storage reduction** with zero loss of cryptographic verifiability. The storage growth rate of a compacted node is $\mathcal{O}(\log |V|)$ rather than $\mathcal{O}(|V|)$.

## 6. Asymptotic Energy Complexity & Sustainability
Legacy Proof of Work protocols rely on global hash rate competition, resulting in an energy expenditure that scales linearly with the network's aggregate computational hardware ($\mathcal{O}(N)$ global energy waste). 

Sikka decouples consensus from block production. Its localized adaptive PoW serves purely as an anti-Sybil rate-limiter. Under non-congested conditions, processing a transaction requires a fixed, constant $\mathcal{O}(1)$ energy expenditure (approximately 4 iterations of SHA3-256). This bounded constraint ensures the network operates sustainably, permitting low-power edge devices (IoT, smartphones) to participate fully without degrading overall state machine security.

## 7. Mathematical Security & Attack Vectors
- **Sybil / Spam Flooding:** As detailed in Algorithm 1, the computational cost to sustain an injection rate $R > BASE\_THROUGHPUT$ grows exponentially. An adversary's required energy vector scales out of bounds within minutes, rendering sustained flooding economically unviable.
- **Pre-computation (Selfish Mining) Attacks:** The PoW hash rigidly commits to the dynamic state of the DAG tips (`ParentPowHashes`). Pre-computed subgraphs immediately invalidate when the honest network's topological frontier advances, neutralizing selfish mining without requiring continuous energy expenditure.

## 8. The Case Against Turing Completeness
Sikka deliberately omits a Turing-complete state transition language (e.g., EVM). Turing completeness fundamentally introduces the Halting Problem, necessitating strict, monetized execution bounds (Gas fees) to prevent infinite loops. By restricting state transitions to deterministic, finite cryptographic validations (UTXO summation, signature verification), Sikka guarantees halting natively. This structural constraint enables the strictly zero-fee paradigm.

## 9. Conclusion
Sikka resolves the fundamental limits of serialized consensus networks by fusing a parallel UTXO DAG structure with localized, adaptive cryptographic puzzles. By discarding global block synchronization, monetized execution environments, and legacy cryptography, Sikka achieves lock-free concurrency, asymptotic probabilistic finality, and post-quantum resilience. The Epoch-Based Witness Compaction protocol further ensures that the ledger's storage complexity remains $\mathcal{O}(\log |V|)$ over its entire lifetime — permanently deleting spent transaction history while preserving a compact, cryptographically verifiable proof of every transaction that ever occurred. Together, these properties establish a mathematically rigorous, long-term sustainable substrate for decentralized value transfer.
