package node

import (
	"context"
	"time"
)

// weightCompactionInterval is how often the node scans the active DAG frontier
// and compacts weight indices for extremely old, saturated transactions.
const weightCompactionInterval = 30 * time.Minute

// runWeightCompactionLoop runs the weight compaction sweep on a fixed interval
// until ctx is cancelled. It calls DAG.CompactWeightIndex() to reclaim memory
// and disk space.
func (n *Node) runWeightCompactionLoop(ctx context.Context) {
	ticker := time.NewTicker(weightCompactionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := n.dag.CompactWeightIndex()
			if count > 0 {
				n.log.Info("weight index compaction complete",
					"compacted_weights", count,
				)
			}
		}
	}
}
