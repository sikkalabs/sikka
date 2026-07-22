//go:build !js

package chain

import "time"

// PruneLosingConflicts physically removes losing double-spend candidates (and
// their descendant subtrees) once prune eligibility rules are met. Returns the
// number of transactions removed.
func (d *DAG) PruneLosingConflicts() int {
	if err := d.beginOp(); err != nil {
		return 0
	}
	defer d.endOp()

	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pruneLosingConflictsLocked(time.Now().Unix())
}

func (d *DAG) pruneLosingConflictsLocked(now int64) int {
	losers := d.prunableConflictLosersLocked(now)
	if len(losers) == 0 {
		return 0
	}
	pruned := d.collectPruneSubtreeLocked(losers)
	if len(pruned) == 0 {
		return 0
	}
	d.removePrunedTxsLocked(pruned)
	if d.db != nil {
		_ = persistPruneLedger(d.db, pruned, d.utxos, d.spendClaims)
	}
	return len(pruned)
}

func (d *DAG) prunableConflictLosersLocked(now int64) map[string]bool {
	losers := make(map[string]bool)
	for _, claims := range d.spendClaims {
		if len(claims) < 2 {
			continue
		}
		winner := canonicalSpenderLocked(d.weights, claims)
		if winner == "" || winner == d.genesis {
			continue
		}
		if d.weights[winner] < d.confirmationThreshold {
			continue
		}

		latestClaimTimestamp := int64(0)
		for _, claimant := range claims {
			tx := d.getTransactionLocked(claimant)
			if tx == nil {
				continue
			}
			if tx.Timestamp > latestClaimTimestamp {
				latestClaimTimestamp = tx.Timestamp
			}
		}
		if now < latestClaimTimestamp+d.conflictPruneGraceSeconds {
			continue
		}

		for _, claimant := range claims {
			if claimant == winner {
				continue
			}
			if d.weights[winner] < d.weights[claimant]+d.confirmationThreshold {
				continue
			}
			losers[claimant] = true
		}
	}
	return losers
}

func (d *DAG) collectPruneSubtreeLocked(roots map[string]bool) []string {
	pruned := make(map[string]bool)
	queue := make([]string, 0, len(roots))
	for id := range roots {
		if id == "" || id == d.genesis {
			continue
		}
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if pruned[id] {
			continue
		}
		pruned[id] = true
		for _, childID := range d.children[id] {
			queue = append(queue, childID)
		}
	}
	out := make([]string, 0, len(pruned))
	for id := range pruned {
		out = append(out, id)
	}
	return out
}

func (d *DAG) removePrunedTxsLocked(prunedIDs []string) {
	pruned := make(map[string]bool, len(prunedIDs))
	for _, id := range prunedIDs {
		pruned[id] = true
	}
	for id := range pruned {
		delete(d.txs, id)
		delete(d.weights, id)
		delete(d.depths, id)
		delete(d.tips, id)
	}
	for parentID, kids := range d.children {
		if pruned[parentID] {
			delete(d.children, parentID)
			continue
		}
		filtered := kids[:0]
		for _, childID := range kids {
			if !pruned[childID] {
				filtered = append(filtered, childID)
			}
		}
		if len(filtered) == 0 {
			delete(d.children, parentID)
		} else {
			d.children[parentID] = filtered
		}
	}
	for id, tx := range d.txs {
		if len(d.children[id]) == 0 && tx != nil {
			d.tips[id] = struct{}{}
		}
	}

	d.rebuildSpendStateLocked()
	d.invalidateOrderCacheLocked()
}
