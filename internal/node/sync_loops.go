package node

import (
	"context"
	"time"
)

func (n *Node) runSyncLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := n.runSyncRound(ctx); err != nil {
			n.recordSyncFailure("", err)
		}
		if pruned := n.dag.PruneLosingConflicts(); pruned > 0 {
			n.log.Info("prune removed losing conflicts", "count", pruned)
		}
		if !waitForFederationDelay(ctx, n.nextSyncLoopDelay()) {
			return
		}
	}
}

func (n *Node) runDiscoveryLoop(ctx context.Context) {
	if err := n.runDiscoveryRound(ctx); err != nil {
		n.recordSyncFailure("", err)
	}

	ticker := time.NewTicker(discoveryLoopInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.runDiscoveryRound(ctx); err != nil {
				n.recordSyncFailure("", err)
			}
		}
	}
}

func (n *Node) pruneKnownNodesLoop(ctx context.Context) {
	ticker := time.NewTicker(nodePruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pruneKnownNodes(time.Now())
		}
	}
}
