package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	"besoeasy/sikka/internal/chain"
)

func (n *Node) syncFromNode(ctx context.Context, nodeURL string) error {
	result, err := n.syncCatchUp(ctx, nodeURL)
	return n.completeSyncAttempt(nodeURL, result, err)
}

func peerSupportsSync(status syncStatusResponse) bool {
	for _, c := range status.Capabilities {
		if c == capabilitySyncV1 {
			return true
		}
	}
	return false
}

// buildSyncHaveList constructs the `have` list for a POST /v1/sync request.
//
// The list is used by the remote as "knowledge anchors". The server will
// compute the full set of txs the caller needs (ancestor closure of the
// server's current tips, minus everything reachable from these anchors).
//
// The list is built as:
//   - First: the caller's actual current open tips (highest priority anchors
//     for the client's true frontier).
//   - Then: linear prefix from the total order (tip, tip-1, tip-2).
//   - Then: exponentially spaced older txs.
//   - Finally: genesis as absolute fallback.
//
// This gives the server excellent coverage of both the client's recent
// frontier and deep history using a small number of IDs.
func buildSyncHaveList(ordered []chain.Transaction, tips []string) []string {
	n := len(ordered)
	if n == 0 {
		return nil
	}

	seen := make(map[string]bool, maxSyncHaveLen)
	var have []string

	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			have = append(have, id)
		}
	}

	// Prioritize the actual open tips first — these are the most valuable
	// anchors for determining exactly which branches the client has.
	for _, t := range tips {
		add(t)
	}

	// Linear prefix: tip, tip-1, tip-2 (from the total order)
	for i := 0; i < syncLinearPrefix && i < n; i++ {
		add(ordered[n-1-i].ID)
	}

	// Exponential walk back from tip
	step := 4
	for len(have) < maxSyncHaveLen {
		pos := n - 1 - step
		if pos <= 0 {
			break
		}
		add(ordered[pos].ID)
		step *= 2
	}

	// Genesis is the unconditional fallback.
	if n > 0 {
		add(ordered[0].ID)
	}

	return have
}

// syncCatchUp performs federation catch-up using POST /v1/sync (sync_v1).
//
// Each page sends a fresh `have` list (rebuilt from the current local DAG).
// The server recomputes the missing set on every request, so the client
// always uses cursor=0 and loops until the server returns an empty page or
// the post-sync status check confirms the frontiers match.
//
// If the remote returns a non-empty `want` list the caller relays those
// transactions back, making the exchange fully bidirectional in a single round.
func (n *Node) syncCatchUp(ctx context.Context, nodeURL string) (syncAttemptResult, error) {
	status, err := n.fetchSyncStatus(ctx, nodeURL)
	if err != nil {
		return syncAttemptResult{}, fmt.Errorf("GET /v1/sync/status: %w", err)
	}
	n.log.Debug("sync status fetched",
		"peer", nodeURL,
		"remote_dag_size", status.DAGSize,
		"remote_tips", shortFingerprint(status.TipsFingerprint),
	)
	if err := n.validateRemoteSyncStatus(nodeURL, status); err != nil {
		return syncAttemptResult{}, err
	}
	if len(status.Addresses) > 0 {
		if _, _, err := n.addKnownPeer(status.Addresses, false, true); err != nil {
			return syncAttemptResult{}, err
		}
	}
	n.updatePeerLastMatched(nodeURL, status.DAGSize)
	if n.localIsCaughtUpWithStatus(status) {
		n.log.Info("sync caught up", "peer", nodeURL, "dag_size", status.DAGSize)
		return syncAttemptResult{}, nil
	}

	imported := 0
	page := 0

	for {
		if ctx.Err() != nil {
			return syncAttemptResult{importedTxCount: imported}, ctx.Err()
		}

		page++
		if page > maxSyncCatchUpPages {
			return syncAttemptResult{importedTxCount: imported},
				fmt.Errorf("sync: exceeded max pages (%d) catching up with %s", maxSyncCatchUpPages, nodeURL)
		}

		ordered := n.dag.OrderedTransactions()
		tips := n.dag.Tips()
		have := buildSyncHaveList(ordered, tips)

		req := syncRequest{
			Have:   have,
			Limit:  syncBatchLimit,
			Cursor: 0, // have is rebuilt each page; server recomputes missing from scratch
		}

		n.log.Debug("sync page request",
			"page", page,
			"peer", nodeURL,
			"have", len(have),
		)
		pageStart := time.Now()

		var resp syncResponse
		if err := n.postJSONAndDecode(ctx,
			joinNodeURL(nodeURL, "/v1/sync"), req, &resp); err != nil {
			n.log.Warn("sync page failed",
				"page", page,
				"peer", nodeURL,
				"duration", time.Since(pageStart).Round(time.Millisecond),
				"err", err,
			)
			return syncAttemptResult{importedTxCount: imported},
				fmt.Errorf("POST /v1/sync page %d: %w", page, err)
		}

		if page == 1 {
			n.log.Debug("sync common base",
				"peer", nodeURL,
				"common_base", shortFingerprint(resp.CommonBase),
				"missing_estimate", resp.Meta.DAGSize-len(ordered),
			)
		}

		// --- import items the remote sent us ---
		batchImported := 0
		skipped := 0
		var needRepair []chain.Transaction
		for i := range resp.Items {
			cpy := resp.Items[i]
			if n.dag.GetTransaction(cpy.ID) != nil {
				skipped++
				continue
			}
			if err := n.dag.SubmitTx(&cpy); err != nil {
				if strings.Contains(err.Error(), "parent tx") &&
					strings.Contains(err.Error(), "not found") {
					needRepair = append(needRepair, cpy)
					continue
				}
				n.log.Warn("sync submit failed",
					"page", page,
					"txid", cpy.ID,
					"peer", nodeURL,
					"err", err,
				)
				return syncAttemptResult{importedTxCount: imported},
					fmt.Errorf("submit synced tx %s from %s: %w", cpy.ID, nodeURL, err)
			}
			batchImported++
		}

		// Repair any txs whose parents weren't in the batch.
		if len(needRepair) > 0 {
			rep, rerr := n.repairMissingAncestorsForBatch(ctx, nodeURL, needRepair)
			if rerr != nil {
				n.log.Warn("sync repair failed", "page", page, "peer", nodeURL, "err", rerr)
			} else if rep > 0 {
				batchImported += rep
				n.log.Debug("sync repaired ancestors", "count", rep, "page", page, "peer", nodeURL)
			}
			for _, cpy := range needRepair {
				if n.dag.GetTransaction(cpy.ID) != nil {
					batchImported++
					continue
				}
				if err := n.dag.SubmitTx(&cpy); err != nil {
					n.log.Warn("sync submit after repair failed", "page", page, "txid", cpy.ID, "err", err)
				}
			}
		}

		// --- bidirectional: fetch tx IDs the remote wants from us ---
		if len(resp.Want) > 0 {
			wantIDs := resp.Want
			if len(wantIDs) > maxBulkTxLookupIDs {
				wantIDs = wantIDs[:maxBulkTxLookupIDs]
			}
			// Collect the txs we actually have from `want`.
			var toSend []string
			for _, id := range wantIDs {
				if n.dag.GetTransaction(id) != nil {
					toSend = append(toSend, id)
				}
			}
			// Push them to the remote via the existing relay path.
			if len(toSend) > 0 {
				n.log.Debug("sync relaying wanted txs", "peer", nodeURL, "count", len(toSend))
				for _, id := range toSend {
					if tx := n.dag.GetTransaction(id); tx != nil {
						cpy := *tx
						n.enqueueRelayTransaction(&cpy, relayContext{})
					}
				}
			}
		}

		imported += batchImported
		n.log.Debug("sync page ok",
			"page", page,
			"peer", nodeURL,
			"duration", time.Since(pageStart).Round(time.Millisecond),
			"received", len(resp.Items),
			"imported", batchImported,
			"skipped", skipped,
			"local_dag", n.dag.Size(),
		)

		if len(resp.Items) == 0 {
			break
		}
		if batchImported == 0 {
			if skipped == len(resp.Items) {
				// Relay (or a prior page) already delivered these txs.
				break
			}
			n.log.Warn("sync stuck",
				"page", page,
				"peer", nodeURL,
				"received", len(resp.Items),
			)
			return syncAttemptResult{importedTxCount: imported},
				fmt.Errorf("sync: stuck behind %s (no progress on page %d)", nodeURL, page)
		}
	}

	// Post-sync verification.
	//
	// With the improved sync_v1 server logic, the server computes the exact
	// set of transactions required for the caller to reach the server's
	// current frontier (ancestor closure of the server's tips, minus
	// closures of the caller's anchors). Therefore a full exchange should
	// bring the two nodes to equivalent frontiers.
	//
	// We still re-check the fingerprint. If it differs it usually means
	// new transactions arrived on the remote during our paginated sync,
	// or we failed to import something. The next scheduled round will
	// pick it up with a fresh (richer) have list.
	status2, err := n.fetchSyncStatus(ctx, nodeURL)
	if err != nil {
		n.log.Warn("sync post-check failed", "peer", nodeURL, "err", err)
		return syncAttemptResult{importedTxCount: imported}, nil
	}
	n.updatePeerLastMatched(nodeURL, status2.DAGSize)

	if n.localIsCaughtUpWithStatus(status2) {
		n.log.Info("sync verified caught up", "peer", nodeURL, "dag_size", status2.DAGSize)
		return syncAttemptResult{importedTxCount: imported}, nil
	}

	n.log.Info("sync tips still differ after catch-up",
		"local_dag", n.dag.Size(),
		"remote_dag", status2.DAGSize,
		"tips_local", shortFingerprint(n.localSyncDAGSummary().TipsFingerprint),
		"tips_remote", shortFingerprint(status2.TipsFingerprint),
	)

	return syncAttemptResult{importedTxCount: imported}, nil
}

func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "..."
}

func (n *Node) completeSyncAttempt(nodeURL string, result syncAttemptResult, err error) error {
	if err != nil {
		n.markNodeFailure(nodeURL, err)
		n.recordSyncFailure(nodeURL, err)
		return err
	}
	n.touchKnownNode(nodeURL)
	if result.importedTxCount > 0 {
		n.adjustNodeScore(nodeURL, cryptoRandIntn(syncScoreRewardMax)+1)
		n.log.Info("sync imported txs", "count", result.importedTxCount, "peer", nodeURL, "dag_size", n.dag.Size())
	} else {
		n.adjustNodeScore(nodeURL, 1)
	}
	n.setNodeLastSync(nodeURL, time.Now())
	n.recordSyncSuccess(nodeURL)
	return nil
}
