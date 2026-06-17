package node

import (
	"context"
	"fmt"
	"strings"

	"besoeasy/sikka"
	"besoeasy/sikka/internal/chain"
)

func (n *Node) validateRemoteSyncStatus(nodeURL string, status syncStatusResponse) error {
	release := sikka.CurrentRelease()
	if status.ProtocolVersion != release.ProtocolVersion {
		return fmt.Errorf("sync protocol mismatch from %s: %s", nodeURL, status.ProtocolVersion)
	}
	if status.GenesisTxID != n.dag.GenesisID() {
		return fmt.Errorf("genesis mismatch from %s", nodeURL)
	}
	return nil
}

func (n *Node) validateAnnouncedPeer(ctx context.Context, rawAddresses []string) ([]string, error) {
	normalizedAddresses, err := n.normalizePeerAddresses(rawAddresses)
	if err != nil {
		return nil, err
	}
	if len(normalizedAddresses) == 0 {
		return nil, nil
	}

	var firstErr error
	for _, address := range normalizedAddresses {
		status, err := n.fetchSyncStatus(ctx, address)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("probe %s: %w", address, err)
			}
			continue
		}
		if err := n.validateRemoteSyncStatus(address, status); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		validatedAddresses := status.Addresses
		if len(validatedAddresses) == 0 {
			validatedAddresses = []string{address}
		}
		validatedAddresses, err = n.normalizePeerAddresses(validatedAddresses)
		if err != nil {
			return nil, err
		}
		if len(validatedAddresses) == 0 {
			return nil, nil
		}
		return validatedAddresses, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, nil
}

func (n *Node) fetchSyncStatus(ctx context.Context, nodeURL string) (syncStatusResponse, error) {
	var status syncStatusResponse
	if err := n.getJSON(ctx, joinNodeURL(nodeURL, "/v1/sync/status"), &status); err != nil {
		return syncStatusResponse{}, err
	}
	return status, nil
}

// fetchTxsByIDs uses the bulk lookup endpoint (POST /v1/txs) on the given peer
// to retrieve full transaction objects by ID. It is used during sync repair
// (e.g. when a page arrives with txs whose parents are not yet present).
func (n *Node) fetchTxsByIDs(ctx context.Context, nodeURL string, ids []string) ([]chain.Transaction, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	// Dedup while preserving order for determinism.
	seen := make(map[string]bool, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}

	var all []chain.Transaction
	for i := 0; i < len(unique); i += maxBulkTxLookupIDs {
		end := i + maxBulkTxLookupIDs
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[i:end]

		var resp txsLookupResponse
		if err := n.postJSONAndDecode(ctx, joinNodeURL(nodeURL, "/v1/txs"), chunk, &resp); err != nil {
			return nil, fmt.Errorf("POST /v1/txs for %d ids: %w", len(chunk), err)
		}
		all = append(all, resp.Items...)
	}
	return all, nil
}

// repairMissingAncestorsForBatch fetches (using /v1/txs on the peer) any
// missing parents required by the supplied batch, plus their recursive
// ancestors, and submits them locally. It returns the number of txs that were
// newly imported during repair. It is used as a belt-and-suspenders mechanism
// during sync (and for fulfilling "want" hints).
func (n *Node) repairMissingAncestorsForBatch(ctx context.Context, nodeURL string, batch []chain.Transaction) (repairedCount int, err error) {
	if len(batch) == 0 {
		return 0, nil
	}

	// pendingIDs: ancestors we know we need but don't have locally and haven't
	// fetched the object for yet.
	pendingIDs := make(map[string]bool)
	for _, tx := range batch {
		for _, pid := range tx.Parents {
			if n.dag.GetTransaction(pid) == nil {
				pendingIDs[pid] = true
			}
		}
	}

	// fetched but not yet successfully submitted locally.
	fetched := make(map[string]chain.Transaction)
	haveObj := make(map[string]bool)

	const maxRounds = 64
	for round := 0; round < maxRounds && (len(pendingIDs) > 0 || len(fetched) > 0); round++ {
		// Fetch next chunk of pending IDs.
		if len(pendingIDs) > 0 {
			toFetch := make([]string, 0, maxBulkTxLookupIDs)
			for id := range pendingIDs {
				if len(toFetch) >= maxBulkTxLookupIDs {
					break
				}
				toFetch = append(toFetch, id)
				delete(pendingIDs, id)
			}
			if len(toFetch) > 0 {
				newTxs, ferr := n.fetchTxsByIDs(ctx, nodeURL, toFetch)
				if ferr != nil {
					return repairedCount, ferr
				}
				for _, nt := range newTxs {
					if !haveObj[nt.ID] {
						fetched[nt.ID] = nt
						haveObj[nt.ID] = true
					}
					for _, pp := range nt.Parents {
						if n.dag.GetTransaction(pp) == nil && !haveObj[pp] {
							pendingIDs[pp] = true
						}
					}
				}
			}
		}

		// Try to submit as many fetched items as possible. Repeat inner loop
		// to handle cases where we just fetched grandparents and can now submit
		// an intermediate parent.
		progress := true
		for progress {
			progress = false
			for id, f := range fetched {
				if n.dag.GetTransaction(id) != nil {
					delete(fetched, id)
					continue
				}
				cpy := f
				if serr := n.dag.SubmitTx(&cpy); serr != nil {
					if strings.Contains(serr.Error(), "parent tx") && strings.Contains(serr.Error(), "not found") {
						for _, pp := range cpy.Parents {
							if n.dag.GetTransaction(pp) == nil && !haveObj[pp] {
								pendingIDs[pp] = true
							}
						}
					}
					// Other errors (pow, etc.) will be surfaced when the original
					// batch item is retried or on next round.
				} else {
					repairedCount++
					delete(fetched, id)
					progress = true
				}
			}
		}
	}

	// Last-chance submits for anything left in fetched.
	for id, f := range fetched {
		if n.dag.GetTransaction(id) != nil {
			continue
		}
		cpy := f
		if serr := n.dag.SubmitTx(&cpy); serr == nil {
			repairedCount++
		}
	}

	return repairedCount, nil
}

func (n *Node) localIsCaughtUpWithStatus(remote syncStatusResponse) bool {
	if remote.DAGSize != n.dag.Size() {
		return false
	}
	// tipsFingerprint is a sha3-256 over the sorted tip IDs. If the frontier
	// set is identical and the count of txs matches, the full DAG content
	// must be identical (all txs are ancestors of the current tips under the
	// append-only DAG rules).
	localSummary := n.localSyncDAGSummary()
	return remote.TipsFingerprint == localSummary.TipsFingerprint
}
