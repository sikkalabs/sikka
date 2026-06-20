package node

import (
	"context"
	"time"
)

// utxoSweepInterval is how often the node scans for and permanently deletes
// canonically spent, fully confirmed UTXOs from memory and disk.
const utxoSweepInterval = 15 * time.Minute

// runUTXOSweepLoop runs the UTXO compaction sweep on a fixed interval until
// ctx is cancelled. It calls DAG.RunUTXOSweep() to reclaim memory and space.
func (n *Node) runUTXOSweepLoop(ctx context.Context) {
	ticker := time.NewTicker(utxoSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := n.dag.RunUTXOSweep()
			if count > 0 {
				n.log.Info("utxo sweep complete",
					"purged_spent_utxos", count,
				)
			}
		}
	}
}
