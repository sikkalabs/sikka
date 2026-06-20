//go:build !js

package chain

import (
	"encoding/json"
	"fmt"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// CanStripWitness reports whether the ML-DSA-87 witness bytes of tx are
// eligible for permanent deletion under the Deep Finality Guard.
//
// Both conditions must be satisfied simultaneously:
//  1. The transaction is older than WitnessMinAgeSecs (180 days).
//  2. Its cumulative PoW weight is at least WitnessMinWeight (1000).
//
// Additionally all outputs of the transaction must already be spent, meaning
// the signature data can never be needed again for UTXO validation.
//
// Stripping is irreversible. The guard is intentionally conservative: a
// network-wide Sybil cluster cannot accumulate 1000 honest weight in under
// 180 days without also being visible to every honest node that independently
// verified the signature at inclusion time.
func CanStripWitness(tx *Transaction, currentWeight int64, allOutputsSpent bool) bool {
	if tx == nil || tx.WitnessStripped {
		return false
	}
	// Genesis has no witnesses.
	if len(tx.Inputs) == 0 {
		return false
	}
	ageSeconds := time.Now().Unix() - tx.Timestamp
	return allOutputsSpent &&
		ageSeconds >= WitnessMinAgeSecs && // MUST be older than 180 days
		currentWeight >= WitnessMinWeight  // MUST have 1000+ cumulative weight
}

// stripTxWitness permanently removes all ML-DSA-87 signature bytes from the
// stored transaction and sets the WitnessStripped flag. The operation is
// atomic within a single bbolt batch write.
//
// This function must only be called after CanStripWitness returns true.
// The in-memory DAG tx map is NOT updated here; call
// markWitnessStrippedMemLocked separately under the DAG write lock.
func stripTxWitness(db *bbolt.DB, txID string) error {
	return db.Batch(func(boltTx *bbolt.Tx) error {
		bkt := boltTx.Bucket([]byte(storageTxsBucket))
		if bkt == nil {
			return fmt.Errorf("txs bucket missing")
		}
		raw := bkt.Get([]byte(txID))
		if raw == nil {
			return fmt.Errorf("tx %s not found in storage", txID)
		}
		var tx Transaction
		if err := json.Unmarshal(raw, &tx); err != nil {
			return fmt.Errorf("unmarshal tx %s: %w", txID, err)
		}
		if tx.WitnessStripped {
			return nil // Already stripped — idempotent.
		}
		// Delete witness bytes from every input.
		for i := range tx.Inputs {
			tx.Inputs[i].Witness = nil
		}
		tx.WitnessStripped = true
		stripped, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("marshal stripped tx %s: %w", txID, err)
		}
		return bkt.Put([]byte(txID), stripped)
	})
}

// markWitnessStrippedMemLocked updates the in-memory transaction record to
// reflect that witness stripping has occurred. Must be called under the DAG
// write lock (d.mu.Lock) after stripTxWitness has committed to disk.
func (d *DAG) markWitnessStrippedMemLocked(txID string) {
	tx := d.txs[txID]
	if tx == nil {
		return
	}
	for i := range tx.Inputs {
		tx.Inputs[i].Witness = nil
	}
	tx.WitnessStripped = true
}

// allOutputsSpentLocked returns true when every UTXO created by tx has been
// consumed by a later confirmed transaction. Must be called under at least a
// read lock (d.mu.RLock).
func (d *DAG) allOutputsSpentLocked(tx *Transaction) bool {
	for i := range tx.Outputs {
		key := utxoKey(tx.ID, i)
		// If the UTXO still exists in the unspent set it is not yet spent.
		if _, unspent := d.utxos[key]; unspent {
			return false
		}
		// If no spend claim has been recorded for this output, it is either
		// not yet referenced or something is wrong — treat as not-spent.
		if len(d.spendClaims[key]) == 0 {
			return false
		}
		// Verify the canonical spender is confirmed.
		winner := canonicalSpenderLocked(d.weights, d.spendClaims[key])
		if winner == "" || d.weights[winner] < d.confirmationThreshold {
			return false
		}
	}
	return true
}

// RunWitnessSweep scans the full transaction set for witnesses that satisfy
// the Deep Finality Guard and strips them from disk and memory. It is designed
// to be called from a low-priority background goroutine at a long interval
// (e.g. every hour) — never from the hot SubmitTx path.
//
// Returns the number of transactions whose witnesses were stripped this pass.
func (d *DAG) RunWitnessSweep() int {
	if err := d.beginOp(); err != nil {
		return 0
	}
	defer d.endOp()

	// Collect eligible candidates under a read lock to minimise lock contention.
	d.mu.RLock()
	type candidate struct {
		id     string
		tx     *Transaction
		weight int64
	}
	var eligible []candidate
	for id, tx := range d.txs {
		if tx == nil || tx.WitnessStripped || len(tx.Inputs) == 0 {
			continue
		}
		weight := d.weights[id]
		if !CanStripWitness(tx, weight, d.allOutputsSpentLocked(tx)) {
			continue
		}
		eligible = append(eligible, candidate{id: id, tx: tx, weight: weight})
	}
	d.mu.RUnlock()

	if len(eligible) == 0 {
		return 0
	}

	stripped := 0
	for _, c := range eligible {
		// Write to disk outside the lock — bbolt handles its own concurrency.
		if err := stripTxWitness(d.db, c.id); err != nil {
			// Non-fatal: log and continue to the next candidate.
			continue
		}
		// Update the in-memory record under the write lock.
		d.mu.Lock()
		d.markWitnessStrippedMemLocked(c.id)
		d.mu.Unlock()
		stripped++
	}
	return stripped
}
