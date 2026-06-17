//go:build !js

package chain

import "sort"

// spendCandidateBetter reports whether candidate a should win over b when both
// claim the same outpoint. Higher cumulative PoW weight wins; equal weight
// breaks on lower tx ID so every node converges on the same canonical spend.
func spendCandidateBetter(weights map[string]int64, a, b string) bool {
	wa := weights[a]
	wb := weights[b]
	if wa != wb {
		return wa > wb
	}
	return a < b
}

func canonicalSpenderLocked(weights map[string]int64, claims []string) string {
	if len(claims) == 0 {
		return ""
	}
	best := claims[0]
	for _, candidate := range claims[1:] {
		if spendCandidateBetter(weights, candidate, best) {
			best = candidate
		}
	}
	return best
}

func appendSpendClaim(claims []string, txID string) []string {
	for _, existing := range claims {
		if existing == txID {
			return claims
		}
	}
	return append(claims, txID)
}

// effectiveTxSet returns the tx IDs that are ledger-effective: each input
// outpoint's canonical spender is this tx, and every spent output was created
// by another effective tx. Competing spends that lose by weight are excluded.
//
// This function must be called with at least a read lock held. It deliberately
// does NOT call orderedTransactionsLocked so that it is safe under an RLock
// (orderedTransactionsLocked writes to d.ordered, which would be a data race
// if another goroutine holds a WLock concurrently). Instead it builds the
// ordered slice directly from the read-only d.txs / d.depths maps.
func (d *DAG) effectiveTxSetLocked() map[string]bool {
	// Build a read-only snapshot of all transactions in topological order
	// (parent-before-child) without touching the shared d.ordered cache.
	ordered := make([]Transaction, 0, len(d.txs))
	for _, tx := range d.txs {
		if tx != nil {
			ordered = append(ordered, *tx)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		li, lj := d.depths[ordered[i].ID], d.depths[ordered[j].ID]
		if li != lj {
			return li < lj
		}
		if ordered[i].Timestamp != ordered[j].Timestamp {
			return ordered[i].Timestamp < ordered[j].Timestamp
		}
		return ordered[i].ID < ordered[j].ID
	})

	effective := make(map[string]bool, len(ordered))
	for _, tx := range ordered {
		if len(tx.Inputs) == 0 {
			effective[tx.ID] = true
			continue
		}
		ok := true
		for _, in := range tx.Inputs {
			if !effective[in.TxID] {
				ok = false
				break
			}
			key := utxoKey(in.TxID, in.Index)
			if canonicalSpenderLocked(d.weights, d.spendClaims[key]) != tx.ID {
				ok = false
				break
			}
		}
		effective[tx.ID] = ok
	}
	return effective
}

// effectiveUTXOsLocked returns outpoints that are spendable under canonical
// conflict resolution.
func (d *DAG) effectiveUTXOsLocked() map[string]*UTXO {
	effective := d.effectiveTxSetLocked()
	available := make(map[string]*UTXO, len(d.utxos))
	for key, utxo := range d.utxos {
		if utxo == nil {
			continue
		}
		if !effective[utxo.TxID] {
			continue
		}
		if canonicalSpenderLocked(d.weights, d.spendClaims[key]) != "" {
			continue
		}
		available[key] = utxo
	}
	return available
}
