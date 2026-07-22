//go:build !js

package chain

import (
	"sort"
)

func (d *DAG) addUTXOToAddrIndexLocked(utxo *UTXO, key string) {
	if d.addrIndex == nil {
		d.addrIndex = make(map[string]map[string]struct{})
	}
	if utxo == nil || utxo.Address == "" {
		return
	}
	set, ok := d.addrIndex[utxo.Address]
	if !ok {
		set = make(map[string]struct{})
		d.addrIndex[utxo.Address] = set
	}
	set[key] = struct{}{}
}

func (d *DAG) removeUTXOFromAddrIndexLocked(address string, key string) {
	if d.addrIndex == nil || address == "" {
		return
	}
	if set, ok := d.addrIndex[address]; ok {
		delete(set, key)
		if len(set) == 0 {
			delete(d.addrIndex, address)
		}
	}
}

// rebuildSpendStateLocked reconstructs outputs and spend claims from all known
// transactions. Called after loading persisted state so every node derives the
// same ledger view from the same DAG content.
func (d *DAG) rebuildSpendStateLocked() {
	d.utxos = make(map[string]*UTXO)
	d.spendClaims = make(map[string][]string)
	d.addrIndex = make(map[string]map[string]struct{})
	for _, tx := range d.txs {
		if tx == nil {
			continue
		}
		depth := d.depths[tx.ID]
		for i, out := range tx.Outputs {
			key := utxoKey(tx.ID, i)
			u := &UTXO{
				TxID:      tx.ID,
				Index:     i,
				Address:   out.Address,
				Value:     out.Value,
				DAGDepth:  depth,
				CreatedAt: tx.Timestamp,
			}
			d.utxos[key] = u
			d.addUTXOToAddrIndexLocked(u, key)
		}
		for _, in := range tx.Inputs {
			key := utxoKey(in.TxID, in.Index)
			d.spendClaims[key] = appendSpendClaim(d.spendClaims[key], tx.ID)
		}
	}

	// Purge confirmed spent UTXOs from memory to save RAM.
	// If a UTXO is canonically spent and the spending transaction is fully confirmed,
	// the UTXO is dead and can never be spent again. We don't need it in memory.
	for key, utxo := range d.utxos {
		claims := d.spendClaims[key]
		if len(claims) > 0 {
			winner := canonicalSpenderLocked(d.weights, claims)
			if winner != "" && d.weights[winner] >= d.confirmationThreshold {
				d.removeUTXOFromAddrIndexLocked(utxo.Address, key)
				delete(d.utxos, key)
			}
		}
	}
}

// rebuildIndexLocked reconstructs children, tips, and depths from txs and weights.
// Called on startup after loading from disk.
func (d *DAG) rebuildIndexLocked() {
	d.children = make(map[string][]string)
	d.tips = make(map[string]struct{})
	d.depths = make(map[string]int64)
	d.invalidateOrderCacheLocked()

	// Build children map.
	for id, tx := range d.txs {
		for _, parentID := range tx.Parents {
			d.children[parentID] = append(d.children[parentID], id)
		}
		// Initially mark everything as a tip.
		d.tips[id] = struct{}{}
	}
	// Remove anything that has children from tips.
	for id := range d.children {
		delete(d.tips, id)
	}

	// Compute depths via topological sort (BFS from genesis).
	if d.genesis == "" {
		for id, tx := range d.txs {
			if len(tx.Parents) == 0 {
				d.genesis = id
				break
			}
		}
	}
	if d.genesis != "" {
		d.computeDepthsBFS()
	}
}

// computeDepthsBFS computes DAG depths via a Kahn-style topological pass.
// Because every non-genesis tx has exactly two parents and parents are always
// added before children, the indegree-driven traversal visits each tx and
// each child edge exactly once (O(N) total) instead of the relax-and-requeue
// behaviour of a plain BFS, which can revisit subtrees on wide DAGs.
func (d *DAG) computeDepthsBFS() {
	indegree := make(map[string]int, len(d.txs))
	for id, tx := range d.txs {
		indegree[id] = len(tx.Parents)
	}

	queue := make([]string, 0, len(d.txs))
	for id, deg := range indegree {
		if deg == 0 {
			d.depths[id] = 0
			queue = append(queue, id)
		}
	}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		myDepth := d.depths[id]
		for _, childID := range d.children[id] {
			if childDepth := myDepth + 1; childDepth > d.depths[childID] {
				d.depths[childID] = childDepth
			}
			indegree[childID]--
			if indegree[childID] == 0 {
				queue = append(queue, childID)
			}
		}
	}
}
func (d *DAG) invalidateOrderCacheLocked() {
	d.ordered = nil
	clear(d.checksums)
}

func (d *DAG) orderedTransactionsLocked() []Transaction {
	if d.ordered != nil {
		return d.ordered
	}

	ordered := make([]Transaction, 0, len(d.depths))
	for id := range d.depths {
		tx := d.getTransactionLocked(id)
		if tx == nil {
			continue
		}
		ordered = append(ordered, *cloneTransaction(tx))
	}

	sort.Slice(ordered, func(i, j int) bool {
		left := ordered[i]
		right := ordered[j]
		leftDepth := d.depths[left.ID]
		rightDepth := d.depths[right.ID]
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		if left.Timestamp != right.Timestamp {
			return left.Timestamp < right.Timestamp
		}
		return left.ID < right.ID
	})

	d.ordered = ordered
	return d.ordered
}
