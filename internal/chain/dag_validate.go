//go:build !js

package chain

import (
	"fmt"
	"sync"
	"time"
)

// ---- SubmitTx three-phase helpers ----

// validateTxStatic runs all non-state-dependent validation. It does not touch
// DAG state and so can run without any lock. It does mutate tx (normalizing
// output addresses in place), matching the prior validateTxLocked behaviour.
func validateTxStatic(tx *Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction is required")
	}
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction must have at least one input")
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction must have at least one output")
	}
	if len(tx.Inputs) > MaxTxInputs {
		return fmt.Errorf("too many inputs: %d > %d", len(tx.Inputs), MaxTxInputs)
	}
	if len(tx.Outputs) > MaxTxOutputs {
		return fmt.Errorf("too many outputs: %d > %d", len(tx.Outputs), MaxTxOutputs)
	}
	if len(tx.Parents) != 2 {
		return fmt.Errorf("transaction must have exactly 2 parents, got %d", len(tx.Parents))
	}
	if tx.Timestamp == 0 {
		return fmt.Errorf("timestamp is required (must be set before mining)")
	}
	if tx.Timestamp > time.Now().Unix()+MaxFutureSkewSeconds {
		return fmt.Errorf("timestamp %d is too far in the future", tx.Timestamp)
	}
	for _, parentID := range tx.Parents {
		if len(parentID) != 64 {
			return fmt.Errorf("parent tx id %q is not a valid 64-char hex string", parentID)
		}
	}

	for i, in := range tx.Inputs {
		if len(in.TxID) != 64 {
			return fmt.Errorf("input %d txid %q is not a valid 64-char hex string", i, in.TxID)
		}
		if in.Index < 0 {
			return fmt.Errorf("input %d index must be non-negative", i)
		}
	}

	var totalOut int64
	for i, out := range tx.Outputs {
		normalizedAddress, err := NormalizeAddress(out.Address)
		if err != nil {
			return fmt.Errorf("output %d address: %w", i, err)
		}
		tx.Outputs[i].Address = normalizedAddress
		if out.Value <= 0 {
			return fmt.Errorf("output %d has non-positive value %d", i, out.Value)
		}
		if out.Value > TotalSupply {
			return fmt.Errorf("output %d value %d exceeds total supply", i, out.Value)
		}
		totalOut += out.Value
		if totalOut > TotalSupply {
			return fmt.Errorf("total output value %d exceeds total supply", totalOut)
		}
	}

	seenInputs := make(map[string]bool, len(tx.Inputs))
	for _, in := range tx.Inputs {
		key := utxoKey(in.TxID, in.Index)
		if seenInputs[key] {
			return fmt.Errorf("duplicate input %s", key)
		}
		seenInputs[key] = true
	}

	return nil
}

// checkInputMaturity verifies that a UTXO may be spent at spendTimestamp.
// The genesis payout is always spendable; all other outputs must have a
// non-zero CreatedAt and satisfy MinUTXOMaturitySeconds.
func checkInputMaturity(genesisID, key string, utxo *UTXO, spendTimestamp int64) error {
	if utxo.TxID == genesisID {
		return nil
	}
	if utxo.CreatedAt == 0 {
		return fmt.Errorf("input %s missing created_at", key)
	}
	if spendTimestamp < utxo.CreatedAt+MinUTXOMaturitySeconds {
		return fmt.Errorf(
			"input %s not yet mature: created at %d, matures at %d, spending tx timestamp %d",
			key, utxo.CreatedAt, utxo.CreatedAt+MinUTXOMaturitySeconds, spendTimestamp,
		)
	}
	return nil
}

// snapshotTxInputsRLocked returns a slice (parallel to tx.Inputs) of UTXO
// copies. It also verifies that all parents currently exist and that the
// timestamp invariant holds against parent timestamps. Holding RLock allows
// many SubmitTx calls to snapshot concurrently.
func (d *DAG) snapshotTxInputsRLocked(tx *Transaction) ([]*UTXO, error) {
	maxParentTimestamp := int64(0)
	for _, parentID := range tx.Parents {
		parent := d.txs[parentID]
		if parent == nil {
			return nil, fmt.Errorf("parent tx %s not found", parentID)
		}
		if parent.Timestamp > maxParentTimestamp {
			maxParentTimestamp = parent.Timestamp
		}
	}
	if tx.Timestamp < maxParentTimestamp {
		return nil, fmt.Errorf("timestamp %d is older than newest parent timestamp %d", tx.Timestamp, maxParentTimestamp)
	}

	spentUTXOs := make([]*UTXO, len(tx.Inputs))
	var totalIn int64
	for i, in := range tx.Inputs {
		key := utxoKey(in.TxID, in.Index)
		utxo, ok := d.utxos[key]
		if !ok {
			return nil, fmt.Errorf("input %s not found", key)
		}
		if err := checkInputMaturity(d.genesis, key, utxo, tx.Timestamp); err != nil {
			return nil, err
		}
		spentUTXOs[i] = cloneUTXO(utxo)
		totalIn += utxo.Value
	}

	var totalOut int64
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	if totalIn != totalOut {
		return nil, fmt.Errorf("inputs sum %d chillar must equal outputs sum %d chillar", totalIn, totalOut)
	}

	return spentUTXOs, nil
}

// finalizeAndAddLocked re-checks every state-dependent invariant under the
// write lock (UTXOs still unspent, parents still valid, PoW threshold under
// current congestion) and then atomically adds tx to the DAG. It assumes
// validateTxStatic and signature verification have already succeeded for tx.
func (d *DAG) finalizeAndAddLocked(tx *Transaction, snapshotUTXOs []*UTXO) error {
	// Re-check parents and timestamp under write lock.
	if err := d.validateTimestampAndParentsLocked(tx); err != nil {
		return err
	}

	// Re-check that referenced outputs still match the snapshot (defensive:
	// rules out a concurrent rewrite that could change the input sum).
	var totalIn int64
	for i, in := range tx.Inputs {
		key := utxoKey(in.TxID, in.Index)
		utxo, ok := d.utxos[key]
		if !ok {
			return fmt.Errorf("input %s not found", key)
		}
		if utxo.Value != snapshotUTXOs[i].Value || utxo.Address != snapshotUTXOs[i].Address {
			return fmt.Errorf("input %s changed between snapshot and commit", key)
		}
		// Re-check maturity under write lock: the live UTXO's CreatedAt is
		// authoritative (snapshot may predate a rebuildSpendStateLocked call).
		if err := checkInputMaturity(d.genesis, key, utxo, tx.Timestamp); err != nil {
			return err
		}
		totalIn += utxo.Value
	}
	var totalOut int64
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	if totalIn != totalOut {
		return fmt.Errorf("inputs sum %d chillar must equal outputs sum %d chillar", totalIn, totalOut)
	}

	// Re-quote PoW under current congestion (may have increased since snapshot).
	quote, err := d.quoteTxPoWLocked(tx)
	if err != nil {
		return err
	}
	ok, err := txMeetsMinPowBits(tx, quote.RequiredBits)
	if err != nil {
		return fmt.Errorf("pow check: %w", err)
	}
	if !ok {
		return fmt.Errorf("insufficient PoW: need %d leading zero bits", quote.RequiredBits)
	}

	tx.ID = computeTxID(tx)
	return d.addTxLocked(tx)
}

func (d *DAG) SubmitTxs(txs []*Transaction) error {
	if len(txs) == 0 {
		return nil
	}

	if err := d.beginOp(); err != nil {
		return err
	}
	defer d.endOp()

	for _, tx := range txs {
		if err := validateTxStatic(tx); err != nil {
			return err
		}
		if tx.ID == "" {
			tx.ID = computeTxID(tx)
		}
	}

	d.mu.RLock()
	allSpentUTXOs := make([][]*UTXO, len(txs))
	tempUTXOs := make(map[string]*UTXO)
	var resolveErr error
	for i, tx := range txs {
		spent := make([]*UTXO, len(tx.Inputs))
		for j, in := range tx.Inputs {
			key := utxoKey(in.TxID, in.Index)
			if u, ok := tempUTXOs[key]; ok {
				// Intra-batch maturity check: this UTXO was created by an
				// earlier tx in the same batch submission.
				if err := checkInputMaturity(d.genesis, key, u, tx.Timestamp); err != nil {
					resolveErr = err
					break
				}
				spent[j] = cloneUTXO(u)
				continue
			}
			if u, ok := d.utxos[key]; ok {
				if err := checkInputMaturity(d.genesis, key, u, tx.Timestamp); err != nil {
					resolveErr = err
					break
				}
				spent[j] = cloneUTXO(u)
				continue
			}
			resolveErr = fmt.Errorf("input %s not found", key)
			break
		}
		if resolveErr != nil {
			break
		}
		allSpentUTXOs[i] = spent
		for j, out := range tx.Outputs {
			tempUTXOs[utxoKey(tx.ID, j)] = &UTXO{
				TxID: tx.ID, Index: j, Address: out.Address, Value: out.Value,
				CreatedAt: tx.Timestamp,
			}
		}
	}
	d.mu.RUnlock()

	if resolveErr != nil {
		return resolveErr
	}

	errs := make(chan error, len(txs))
	var wg sync.WaitGroup
	// Limit concurrency for signature verification
	sem := make(chan struct{}, 8)
	for i, tx := range txs {
		i, tx := i, tx
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for j := range tx.Inputs {
				if err := verifyInputWitness(tx, j, allSpentUTXOs[i][j]); err != nil {
					errs <- fmt.Errorf("tx %s input %d: %w", tx.ID, j, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var allWeightUpdates = make(map[string]int64)
	var allSpendClaims = make(map[string][]string)
	var allNewUTXOs = make(map[string]*UTXO)

	for i, tx := range txs {
		// Re-check invariants under lock. Note: if a tx depends on a previous tx in the batch,
		// we pass the simulated snapshot.
		if err := d.validateTimestampAndParentsLocked(tx); err != nil {
			return err
		}

		var totalIn int64
		for j, in := range tx.Inputs {
			key := utxoKey(in.TxID, in.Index)
			// It might be in d.utxos or in our allNewUTXOs (if created in this batch)
			var utxo *UTXO
			if u, ok := d.utxos[key]; ok {
				utxo = u
			} else if u, ok := allNewUTXOs[key]; ok {
				utxo = u
			}
			if utxo == nil {
				return fmt.Errorf("input %s not found", key)
			}
			if utxo.Value != allSpentUTXOs[i][j].Value || utxo.Address != allSpentUTXOs[i][j].Address {
				return fmt.Errorf("input %s changed", key)
			}
			// Re-check maturity under write lock.
			if err := checkInputMaturity(d.genesis, key, utxo, tx.Timestamp); err != nil {
				return err
			}
			totalIn += utxo.Value
		}
		var totalOut int64
		for _, out := range tx.Outputs {
			totalOut += out.Value
		}
		if totalIn != totalOut {
			return fmt.Errorf("inputs sum %d must equal outputs sum %d", totalIn, totalOut)
		}

		quote, err := d.quoteTxPoWLocked(tx)
		if err != nil {
			return err
		}
		ok, err := txMeetsMinPowBits(tx, quote.RequiredBits)
		if err != nil {
			return fmt.Errorf("pow check: %w", err)
		}
		if !ok {
			return fmt.Errorf("insufficient PoW: need %d leading zero bits", quote.RequiredBits)
		}

		wu, sk, nu, err := d.prepareTxLocked(tx)
		if err != nil {
			return err
		}
		for k, v := range wu {
			// Use max() semantics: multiple txs in the same batch may propagate
			// weight to a shared ancestor. The in-memory commitTxMemLocked path
			// handles this correctly (each commit reads the already-updated
			// d.weights), but the persisted allWeightUpdates snapshot is built
			// before commit, so a plain "=" would silently overwrite an earlier
			// tx's larger contribution. Take the maximum to stay consistent.
			if v > allWeightUpdates[k] {
				allWeightUpdates[k] = v
			}
		}
		for _, key := range sk {
			allSpendClaims[key] = appendSpendClaim(allSpendClaims[key], tx.ID)
		}
		for k, v := range nu {
			allNewUTXOs[k] = v
		}

		d.commitTxMemLocked(tx, wu, sk, nu)
	}

	if d.db != nil {
		if err := persistAddTxs(d.db, txs, allWeightUpdates, allSpendClaims, allNewUTXOs); err != nil {
			return err
		}
	}
	return nil
}
