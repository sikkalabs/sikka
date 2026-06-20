//go:build !js

package chain

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"

	bbolt "go.etcd.io/bbolt"
)

// DAG is the Sikka directed acyclic graph of transactions.
// Each transaction references two parent transactions (except genesis).
// Confirmation is determined by cumulative PoW weight. Competing spends of
// the same outpoint coexist in the DAG; the ledger picks the canonical spend
// by highest cumulative weight (lower tx ID on ties).
type DAG struct {
	mu          sync.RWMutex
	closeOnce   sync.Once
	closeErr    error
	activeOps   sync.WaitGroup
	genesis     string                  // genesis tx ID
	txs         map[string]*Transaction // all known txs
	weights     map[string]int64        // cumulative PoW weight per tx ID
	children    map[string][]string     // tx ID → child tx IDs
	tips        map[string]struct{}     // tx IDs with no children yet
	depths      map[string]int64        // longest path from genesis
	utxos       map[string]*UTXO        // "txid:index" → output metadata (all created outputs)
	spendClaims map[string][]string     // "txid:index" → competing spending tx IDs
	ordered     []Transaction
	checksums   map[int][]string
	db          *bbolt.DB
	dbClosed    bool
	dataFile    string

	// confirmationThreshold is the minimum cumulative PoW weight for confirmation.
	confirmationThreshold int64
	// minPowBits overrides per-tx PoW requirement. 0 = use RequiredTxWork formula.
	minPowBits int
	// conflictPruneGraceSeconds overrides ConflictPruneGraceSeconds when > 0.
	conflictPruneGraceSeconds int64
}

// Options configures a DAG instance.
type Options struct {
	DataDir               string
	ConfirmationThreshold int64
	// MinPowBits overrides the per-tx PoW requirement. 0 means use
	// the congestion-based protocol rule.
	// Set to a small value (e.g. 1) for tests.
	MinPowBits int
	// ConflictPruneGraceSeconds overrides the default losing-spend retention
	// window. Zero uses ConflictPruneGraceSeconds from the protocol.
	ConflictPruneGraceSeconds int64
	// GenesisAddress is the bech32m address that receives TotalSupply in the
	// genesis tx. If empty, the network default genesis address is used.
	GenesisAddress string
}

// NewDAG creates or loads a DAG. If DataDir is empty the DAG is in-memory only.
func NewDAG(opts Options) (*DAG, error) {
	threshold := opts.ConfirmationThreshold
	if threshold <= 0 {
		threshold = DefaultConfirmationThreshold
	}

	d := &DAG{
		txs:                   make(map[string]*Transaction),
		weights:               make(map[string]int64),
		children:              make(map[string][]string),
		tips:                  make(map[string]struct{}),
		depths:                make(map[string]int64),
		utxos:                 make(map[string]*UTXO),
		spendClaims:           make(map[string][]string),
		checksums:             make(map[int][]string),
		confirmationThreshold: threshold,
		minPowBits:            opts.MinPowBits,
	}
	if opts.ConflictPruneGraceSeconds > 0 {
		d.conflictPruneGraceSeconds = opts.ConflictPruneGraceSeconds
	} else {
		d.conflictPruneGraceSeconds = ConflictPruneGraceSeconds
	}

	if opts.DataDir != "" {
		if err := os.MkdirAll(opts.DataDir, 0o755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
		d.dataFile = filepath.Join(opts.DataDir, "dag.db")
		db, err := openStorage(d.dataFile, false)
		if err != nil {
			return nil, err
		}
		if err := initBuckets(db); err != nil {
			db.Close()
			return nil, err
		}
		d.db = db

		txs, weights, utxos, spendClaims, err := loadDAGState(db)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("load dag state: %w", err)
		}
		if len(txs) > 0 {
			d.txs = txs
			d.weights = weights
			d.utxos = utxos
			d.spendClaims = spendClaims
			d.rebuildIndexLocked()
			d.rebuildSpendStateLocked()
			return d, nil
		}
	}

	// Bootstrap genesis.
	genesisAddr := opts.GenesisAddress
	genesis := buildGenesisTx(genesisAddr)
	if err := d.addTxLocked(genesis); err != nil {
		if d.db != nil {
			if closeErr := d.db.Close(); closeErr != nil {
				return nil, fmt.Errorf("add genesis tx: %w (close db: %v)", err, closeErr)
			}
		}
		return nil, fmt.Errorf("add genesis tx: %w", err)
	}
	return d, nil
}

// Close marks the DAG closed, waits for in-flight mutating operations to
// finish, then releases the underlying database. Close is safe to call
// multiple times and from multiple goroutines; only the first call closes
// the database.
func (d *DAG) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.dbClosed = true
		d.mu.Unlock()

		d.activeOps.Wait()

		d.mu.Lock()
		defer d.mu.Unlock()
		if d.db != nil {
			d.closeErr = d.db.Close()
			d.db = nil
		}
	})
	return d.closeErr
}

func (d *DAG) beginOp() error {
	d.mu.RLock()
	if d.dbClosed {
		d.mu.RUnlock()
		return ErrDAGClosed
	}
	d.activeOps.Add(1)
	d.mu.RUnlock()
	return nil
}

func (d *DAG) endOp() {
	d.activeOps.Done()
}

// SubmitTx validates and adds a transaction to the DAG.
// tx.Timestamp must be set by the caller before PoW mining; SubmitTx does not
// auto-assign it because the timestamp is part of the PoW hash.
//
// Validation is split into three phases so that the expensive ML-DSA-87
// signature verification step does not serialize all writers:
//
//  1. validateTxStatic       — no lock: structural / format / PoW value /
//     output sum / input dedup / address normalization.
//  2. snapshotTxInputsRLocked — RLock: copy parent timestamps and the input
//     UTXOs out of the DAG so concurrent submits can read in parallel.
//  3. verifyInputWitness loop — no lock: signature verification (ML-DSA-87
//     is ~ms-scale; running it without the lock lets independent submits
//     verify concurrently).
//  4. finalizeAndAddLocked    — WLock: re-check state-dependent invariants
//     (UTXOs still unspent, PoW threshold still met under current
//     congestion, parents still valid) and write.
func (d *DAG) SubmitTx(tx *Transaction) error {
	if err := d.beginOp(); err != nil {
		return err
	}
	defer d.endOp()

	if err := validateTxStatic(tx); err != nil {
		return err
	}

	d.mu.RLock()
	spentUTXOs, err := d.snapshotTxInputsRLocked(tx)
	d.mu.RUnlock()
	if err != nil {
		return err
	}

	// Signature verification without holding the lock: lets multiple
	// in-flight SubmitTx calls verify in parallel.
	for i := range tx.Inputs {
		if err := verifyInputWitness(tx, i, spentUTXOs[i]); err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	return d.finalizeAndAddLocked(tx, spentUTXOs)
}

// TxPowQuote describes the live PoW requirement for a candidate transaction.
type TxPowQuote struct {
	RequiredBits      int      `json:"required_bits"`
	BaseBits          int      `json:"base_bits"`
	RecentCount       int      `json:"recent_count"`
	CongestionBuckets int      `json:"congestion_buckets"`
	WindowSeconds     int64    `json:"window_seconds"`
	BucketTx          int      `json:"bucket_tx"`
	BucketBits        int      `json:"bucket_bits"`
	OverrideBits      int      `json:"override_bits,omitempty"`
	ParentPowHashes   []string `json:"parent_pow_hashes,omitempty"`
}

// QuoteTxPoW returns the current PoW requirement for a candidate transaction.
func (d *DAG) QuoteTxPoW(tx *Transaction) (TxPowQuote, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.quoteTxPoWLocked(tx)
}

// GetTransaction returns a transaction by ID, or nil if not found.
func (d *DAG) GetTransaction(id string) *Transaction {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tx := d.txs[id]
	if tx == nil {
		return nil
	}
	return cloneTransaction(tx)
}

// FillParentPowHashes populates tx.ParentPowHashes with the current PoW hashes
// of the transactions referenced by tx.Parents. This must be called after
// setting tx.Parents (via SelectTips) and before calling MineTxPoW, so that
// the PoW work is cryptographically committed to the current DAG tip state.
//
// Typical wallet flow:
//
//	tip1, tip2 := dag.SelectTips()
//	tx.Parents = []string{tip1, tip2}
//	if err := dag.FillParentPowHashes(tx); err != nil { ... }
//	if err := chain.MineTxPoW(ctx, tx, bits); err != nil { ... }
//	dag.SubmitTx(tx)
func (d *DAG) FillParentPowHashes(tx *Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction is required")
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	hashes := make([]string, len(tx.Parents))
	for i, parentID := range tx.Parents {
		parent := d.txs[parentID]
		if parent == nil {
			return fmt.Errorf("parent tx %s not found in DAG", parentID)
		}
		h, err := txPowHash(parent)
		if err != nil {
			return fmt.Errorf("parent %s pow hash: %w", parentID, err)
		}
		hashes[i] = fmt.Sprintf("%x", h)
	}
	tx.ParentPowHashes = hashes
	return nil
}

// GetUTXOs returns ledger-effective unspent outputs for an address, sorted by
// dag_depth. Competing spends resolve by cumulative PoW weight (lower tx ID
// on ties) so every node converges on the same spendable set.
func (d *DAG) GetUTXOs(address string) []*UTXO {
	d.mu.RLock()
	defer d.mu.RUnlock()
	available := d.effectiveUTXOsLocked()
	var out []*UTXO
	for _, u := range available {
		if u.Address == address {
			out = append(out, cloneUTXO(u))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DAGDepth < out[j].DAGDepth })
	return out
}

// GetBalance returns the total unspent balance for an address.
func (d *DAG) GetBalance(address string) int64 {
	var total int64
	for _, u := range d.GetUTXOs(address) {
		total += u.Value
	}
	return total
}

// Tips returns the current tip tx IDs (txs with no children).
func (d *DAG) Tips() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tips := make([]string, 0, len(d.tips))
	for id := range d.tips {
		tips = append(tips, id)
	}
	return tips
}

// TxWeight returns the cumulative PoW weight of a tx ID.
func (d *DAG) TxWeight(id string) int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.txWeightLocked(id)
}

// IsConfirmed returns true when the cumulative weight for id meets the threshold.
func (d *DAG) IsConfirmed(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.txWeightLocked(id) >= d.confirmationThreshold
}

// txWeightLocked returns the actual weight or infers saturation if compacted.
func (d *DAG) txWeightLocked(id string) int64 {
	if w, ok := d.weights[id]; ok {
		return w
	}
	// Weight index compaction: if a weight is missing but the transaction
	// is deep enough behind the current active frontier, we assume it has
	// reached saturation (it would have been pruned if it was a losing branch).
	depth := d.depths[id]
	if depth > 0 && d.maxDepthLocked()-depth > WeightCompactionDepth {
		return d.weightSaturationLocked()
	}
	return 0
}

// maxDepthLocked returns the current maximum dag depth without taking the RLock.
func (d *DAG) maxDepthLocked() int64 {
	var max int64
	for id := range d.tips {
		if dep := d.depths[id]; dep > max {
			max = dep
		}
	}
	return max
}

// DAGDepth returns the longest-path depth of a tx from genesis (0 = genesis).
func (d *DAG) DAGDepth(id string) int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.depths[id]
}

// MaxDepth returns the current maximum dag depth across all tips.
func (d *DAG) MaxDepth() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.maxDepthLocked()
}

// GenesisID returns the genesis transaction ID.
func (d *DAG) GenesisID() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.genesis
}

// cryptoRandInt63n returns an unbiased random int64 in [0, n) using
// crypto/rand with rejection sampling. It panics if n <= 0 or if the system
// RNG fails (treated as unrecoverable, like a missing /dev/urandom).
func cryptoRandInt63n(n int64) int64 {
	if n <= 0 {
		panic(fmt.Sprintf("cryptoRandInt63n: n must be positive, got %d", n))
	}
	v, err := cryptorand.Int(cryptorand.Reader, big.NewInt(n))
	if err != nil {
		panic(fmt.Sprintf("cryptoRandInt63n: crypto/rand failed: %v", err))
	}
	return v.Int64()
}

// SelectTips picks two tip IDs for a new transaction to reference.
// Uses a weighted random walk (MCMC): starts from a random tip and walks
// backwards/forwards biased by weight. Returns the genesis ID twice when
// there is only one tip.
func (d *DAG) SelectTips() (string, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	tips := make([]string, 0, len(d.tips))
	for id := range d.tips {
		tips = append(tips, id)
	}
	if len(tips) == 0 {
		return d.genesis, d.genesis
	}
	if len(tips) == 1 {
		return tips[0], tips[0]
	}

	// Weight-biased random selection: pick two distinct tips.
	pick := func(exclude string) string {
		totalWeight := int64(0)
		for _, id := range tips {
			if id == exclude {
				continue
			}
			w := d.weights[id] + 1 // +1 to avoid zero-weight tips being excluded
			totalWeight += w
		}
		if totalWeight == 0 {
			for _, id := range tips {
				if id != exclude {
					return id
				}
			}
			return tips[0]
		}
		r := cryptoRandInt63n(totalWeight)
		for _, id := range tips {
			if id == exclude {
				continue
			}
			w := d.weights[id] + 1
			r -= w
			if r < 0 {
				return id
			}
		}
		for _, id := range tips {
			if id != exclude {
				return id
			}
		}
		return tips[0]
	}

	p1 := pick("")
	p2 := pick(p1)
	return p1, p2
}

// Size returns the number of transactions in the DAG.
func (d *DAG) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.txs)
}

// OrderedTransactions returns all transactions in a deterministic topological
// order suitable for chunked sync. Parents always sort before children because
// DAG depth is defined as max(parent depth)+1.
func (d *DAG) OrderedTransactions() []Transaction {
	d.mu.RLock()
	if d.ordered != nil {
		ordered := append([]Transaction(nil), d.ordered...)
		d.mu.RUnlock()
		return ordered
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	ordered := d.orderedTransactionsLocked()
	return append([]Transaction(nil), ordered...)
}

// OrderedTransactionChecksums returns deterministic chunk checksums for the
// current ordered transaction view.
func (d *DAG) OrderedTransactionChecksums(chunkSize int, checksum func([]Transaction) string) []string {
	if chunkSize <= 0 || checksum == nil {
		return nil
	}

	d.mu.RLock()
	if cached, ok := d.checksums[chunkSize]; ok {
		checksums := append([]string(nil), cached...)
		d.mu.RUnlock()
		return checksums
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if cached, ok := d.checksums[chunkSize]; ok {
		return append([]string(nil), cached...)
	}

	ordered := d.orderedTransactionsLocked()
	if len(ordered) == 0 {
		d.checksums[chunkSize] = []string{}
		return []string{}
	}

	checksums := make([]string, 0, (len(ordered)+chunkSize-1)/chunkSize)
	for start := 0; start < len(ordered); start += chunkSize {
		end := start + chunkSize
		if end > len(ordered) {
			end = len(ordered)
		}
		checksums = append(checksums, checksum(ordered[start:end]))
	}
	d.checksums[chunkSize] = append([]string(nil), checksums...)
	return checksums
}
