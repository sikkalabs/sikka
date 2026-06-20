package node

import (
	"context"
	"time"
)

// witnessSweepInterval is how often the node scans the DAG for transactions
// whose ML-DSA-87 witnesses are eligible for permanent deletion under the
// Deep Finality Guard (180 days + weight ≥ 1000).
//
// Intentionally long: witness stripping is a background, low-priority task.
// Running it hourly avoids any impact on the SubmitTx hot path.
const witnessSweepInterval = 1 * time.Hour

// runWitnessSweepLoop runs the witness compaction sweep on a fixed interval
// until ctx is cancelled. Each pass calls DAG.RunWitnessSweep(), which
// identifies confirmed, fully-spent transactions older than 180 days with
// cumulative weight ≥ 1000, then permanently deletes their signature bytes.
func (n *Node) runWitnessSweepLoop(ctx context.Context) {
	// Stagger the first run by the full interval so the node has time to
	// finish syncing before it begins compacting historical witnesses.
	ticker := time.NewTicker(witnessSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := n.dag.RunWitnessSweep()
			if count > 0 {
				n.log.Info("witness sweep complete",
					"stripped_txs", count,
					"guard_age_days", 180,
					"guard_min_weight", 1000,
				)
			}
		}
	}
}
