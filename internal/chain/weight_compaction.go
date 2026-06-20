//go:build !js

package chain

import (
	"fmt"

	bbolt "go.etcd.io/bbolt"
)

// persistDeleteWeight permanently deletes a cumulative weight index from the DB.
func persistDeleteWeight(db *bbolt.DB, id string) error {
	return db.Batch(func(boltTx *bbolt.Tx) error {
		bkt := boltTx.Bucket([]byte(storageWeightsBucket))
		if bkt == nil {
			return fmt.Errorf("weights bucket missing")
		}
		return bkt.Delete([]byte(id))
	})
}

// CompactWeightIndex deletes cumulative weight indices for transactions that
// are deep enough behind the current active DAG frontier (WeightCompactionDepth).
//
// Because weights saturate at a maximum deterministic value, any transaction
// that is older than the compaction depth and still in the DAG is mathematically
// guaranteed to be fully saturated (otherwise it would have been pruned as an
// orphaned losing conflict long ago). We can therefore safely drop its explicit
// weight integer from memory and disk and infer its saturation on the fly.
//
// Returns the number of weight indices compacted.
func (d *DAG) CompactWeightIndex() int {
	if err := d.beginOp(); err != nil {
		return 0
	}
	defer d.endOp()

	d.mu.RLock()
	currentMaxDepth := d.maxDepthLocked()
	var eligible []string
	
	// Identify transactions that have a stored weight but are very deep.
	for id := range d.weights {
		depth, ok := d.depths[id]
		if ok && currentMaxDepth-depth > WeightCompactionDepth {
			eligible = append(eligible, id)
		}
	}
	d.mu.RUnlock()

	if len(eligible) == 0 {
		return 0
	}

	compacted := 0
	for _, id := range eligible {
		// Delete from disk outside the DAG lock
		if d.db != nil {
			if err := persistDeleteWeight(d.db, id); err != nil {
				continue
			}
		}

		// Delete from memory
		d.mu.Lock()
		delete(d.weights, id)
		d.mu.Unlock()
		compacted++
	}

	return compacted
}
