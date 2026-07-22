//go:build !js

package chain

import (
	"math"
)

func (d *DAG) weightUpdatesForTxLocked(tx *Transaction, delta int64) map[string]int64 {
	saturation := d.weightSaturationLocked()
	newSelf := d.weights[tx.ID] + delta
	if newSelf > saturation {
		newSelf = saturation
	}
	updates := map[string]int64{tx.ID: newSelf}
	visited := make(map[string]bool)
	queue := append([]string(nil), tx.Parents...)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true

		current := d.weights[id]
		if current >= saturation {
			// weight[parent] >= weight[child] is an invariant of monotonic
			// propagation, so once we hit a saturated ancestor every
			// ancestor reachable from it is also saturated. Prune.
			continue
		}
		newW := current + delta
		if newW > saturation {
			newW = saturation
		}
		updates[id] = newW
		parent := d.getTransactionLocked(id)
		if parent == nil {
			continue
		}
		queue = append(queue, parent.Parents...)
	}
	return updates
}

// weightSaturationLocked returns the cumulative-weight ceiling beyond which
// propagation is pruned. It is a deterministic function of
// confirmationThreshold so every node computes the same value.
func (d *DAG) weightSaturationLocked() int64 {
	if d.confirmationThreshold <= 0 {
		return math.MaxInt64
	}
	if d.confirmationThreshold > math.MaxInt64/weightSaturationFactor {
		return math.MaxInt64
	}
	return d.confirmationThreshold * weightSaturationFactor
}

// propagateWeightLocked walks all ancestors of startID (via parents) and
// increments their cumulative weight by delta, with the same saturation
// pruning as weightUpdatesForTxLocked so persisted weight values stay
// deterministic and bounded.
func (d *DAG) propagateWeightLocked(startID string, delta int64) {
	saturation := d.weightSaturationLocked()
	if w := d.weights[startID] + delta; w > saturation {
		d.weights[startID] = saturation
	} else {
		d.weights[startID] = w
	}

	visited := make(map[string]bool)
	queue := []string{startID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		tx := d.getTransactionLocked(id)
		if tx == nil {
			continue
		}
		for _, parentID := range tx.Parents {
			if visited[parentID] {
				continue
			}
			visited[parentID] = true
			current := d.weights[parentID]
			if current >= saturation {
				// Saturated: by the parent>=child weight invariant, all
				// further ancestors via this branch are also saturated.
				continue
			}
			if w := current + delta; w > saturation {
				d.weights[parentID] = saturation
			} else {
				d.weights[parentID] = w
			}
			queue = append(queue, parentID)
		}
	}
}
