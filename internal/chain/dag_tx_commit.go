//go:build !js

package chain

import (
	"fmt"
	"sort"
	"time"
)

func (d *DAG) validateTimestampAndParentsLocked(tx *Transaction) error {
	// Require a non-zero timestamp. The timestamp is part of the PoW hash and
	// the txID, so it must be fixed before mining and must not change.
	if tx.Timestamp == 0 {
		return fmt.Errorf("timestamp is required (must be set before mining)")
	}
	now := time.Now().Unix()
	if tx.Timestamp > now+MaxFutureSkewSeconds {
		return fmt.Errorf("timestamp %d is too far in the future", tx.Timestamp)
	}

	// Genesis transactions have no parents; skip parent checks entirely.
	if len(tx.Parents) == 0 {
		return nil
	}

	// Tips commitment: tx.ParentPowHashes must be present for non-genesis txs
	// and must exactly match the PoW hashes of the declared parent transactions.
	// This binds the PoW work to a specific DAG state, preventing selfish
	// mining (pre-mining against old tips produces wrong ParentPowHashes).
	if len(tx.ParentPowHashes) != len(tx.Parents) {
		return fmt.Errorf(
			"parent_pow_hashes length %d must equal parents length %d",
			len(tx.ParentPowHashes), len(tx.Parents),
		)
	}

	maxParentTimestamp := int64(0)
	for i, parentID := range tx.Parents {
		if len(parentID) != 64 {
			return fmt.Errorf("parent tx id %q is not a valid 64-char hex string", parentID)
		}
		parent := d.getTransactionLocked(parentID)
		if parent == nil {
			return fmt.Errorf("parent tx %s not found", parentID)
		}
		if parent.Timestamp > maxParentTimestamp {
			maxParentTimestamp = parent.Timestamp
		}

		// Verify that the claimed parent PoW hash matches what the DAG computed.
		expectedHash, err := txPowHash(parent)
		if err != nil {
			return fmt.Errorf("parent %s pow hash: %w", parentID, err)
		}
		expectedHex := fmt.Sprintf("%x", expectedHash)
		if tx.ParentPowHashes[i] != expectedHex {
			return fmt.Errorf(
				"parent_pow_hashes[%d] %q does not match parent %s actual PoW hash %q: "+
					"PoW was mined against a stale or incorrect DAG state",
				i, tx.ParentPowHashes[i], parentID, expectedHex,
			)
		}
	}
	if tx.Timestamp < maxParentTimestamp {
		return fmt.Errorf("timestamp %d is older than newest parent timestamp %d", tx.Timestamp, maxParentTimestamp)
	}
	return nil
}

func (d *DAG) addTxLocked(tx *Transaction) error {
	weightUpdates, spentKeys, newUTXOs, err := d.prepareTxLocked(tx)
	if err != nil {
		return err
	}
	if d.db != nil {
		if err := persistAddTx(d.db, tx, weightUpdates, spentKeys, newUTXOs); err != nil {
			return err
		}
	}
	d.commitTxMemLocked(tx, weightUpdates, spentKeys, newUTXOs)
	return nil
}

func (d *DAG) prepareTxLocked(tx *Transaction) (map[string]int64, []string, map[string]*UTXO, error) {
	if tx.ID == "" {
		tx.ID = computeTxID(tx)
	}
	if d.getTransactionLocked(tx.ID) != nil {
		return nil, nil, nil, fmt.Errorf("transaction %s already in DAG", tx.ID)
	}

	// Compute PowBits if not set.
	if tx.PowBits == 0 && (len(tx.Inputs) > 0 || len(tx.Parents) > 0) {
		bits, err := txPowLeadingZeroBits(tx)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("compute pow bits: %w", err)
		}
		tx.PowBits = bits
	}

	// Compute DAG depth as max(parent depths) + 1.
	var depth int64
	for _, parentID := range tx.Parents {
		if pd := d.depths[parentID]; pd+1 > depth {
			depth = pd + 1
		}
	}

	// Update weights: add this tx's PowBits to all ancestors.
	powContribution := int64(tx.PowBits)
	if powContribution == 0 {
		powContribution = 1 // genesis and low-PoW txs contribute at least 1
	}
	weightUpdates := d.weightUpdatesForTxLocked(tx, powContribution)

	newUTXOs := make(map[string]*UTXO, len(tx.Outputs))
	spentKeys := make([]string, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		key := utxoKey(in.TxID, in.Index)
		spentKeys = append(spentKeys, key)
	}
	for i, out := range tx.Outputs {
		key := utxoKey(tx.ID, i)
		newUTXOs[key] = &UTXO{
			TxID:      tx.ID,
			Index:     i,
			Address:   out.Address,
			Value:     out.Value,
			DAGDepth:  depth,
			CreatedAt: tx.Timestamp,
		}
	}

	// Temporary depth so that weightUpdatesForTxLocked doesn't fail? No, wait!
	// prepareTxLocked does not modify memory.
	return weightUpdates, spentKeys, newUTXOs, nil
}

func (d *DAG) commitTxMemLocked(tx *Transaction, weightUpdates map[string]int64, spentKeys []string, newUTXOs map[string]*UTXO) {
	// The depth was already calculated in prepareTxLocked, but we need it here.
	var depth int64
	for _, parentID := range tx.Parents {
		if pd := d.depths[parentID]; pd+1 > depth {
			depth = pd + 1
		}
	}

	d.depths[tx.ID] = depth
	d.txs[tx.ID] = tx
	d.ingestedCount++
	d.ingestHistory = append(d.ingestHistory, time.Now().Unix())
	d.offloadHistoricalTxsLocked()

	// Maintain the ordered cache incrementally instead of full rebuild.
	// This avoids O(N) map iteration + O(N log N) sort on every Submit for large DAGs.
	// New transactions always have depth > parents' depths. When their depth is
	// >= the previous tail's depth they can be appended and only the affected
	// same-depth cohort needs re-sorting. If a lower-depth tx arrives (late
	// branch/side tx or catch-up of alternate history), fall back to nil so the
	// next demand for OrderedTransactions() gets a correct full sort.
	clear(d.checksums)
	if d.ordered != nil {
		cloned := *cloneTransaction(tx)
		d.ordered = append(d.ordered, cloned)
		myDepth := d.depths[tx.ID]
		lastIdx := len(d.ordered) - 2
		if lastIdx >= 0 && d.depths[d.ordered[lastIdx].ID] > myDepth {
			// low-depth arrival relative to current frontier: invalidate cache
			// for a correct full rebuild on next use
			d.ordered = nil
		} else {
			groupStart := len(d.ordered) - 1
			for i := lastIdx; i >= 0; i-- {
				if d.depths[d.ordered[i].ID] < myDepth {
					groupStart = i + 1
					break
				}
			}
			sort.Slice(d.ordered[groupStart:], func(i, j int) bool {
				a := d.ordered[groupStart+i]
				b := d.ordered[groupStart+j]
				if a.Timestamp != b.Timestamp {
					return a.Timestamp < b.Timestamp
				}
				return a.ID < b.ID
			})
		}
	}

	for _, parentID := range tx.Parents {
		d.children[parentID] = append(d.children[parentID], tx.ID)
		delete(d.tips, parentID)
	}

	d.tips[tx.ID] = struct{}{}
	for txID, weight := range weightUpdates {
		d.weights[txID] = weight
	}

	for _, key := range spentKeys {
		d.spendClaims[key] = appendSpendClaim(d.spendClaims[key], tx.ID)
	}
	for key, utxo := range newUTXOs {
		d.utxos[key] = utxo
	}

	if d.genesis == "" {
		d.genesis = tx.ID
	}
	d.pruneLosingConflictsLocked(time.Now().Unix())
}
