package node

import (
	"context"
	"fmt"
	"net/url"
)

func (n *Node) runDiscoveryRound(ctx context.Context) error {
	candidates := n.availableNodeURLs(0)
	if len(candidates) == 0 {
		return nil
	}
	n.log.Debug("discovery round starting", "candidates", len(candidates))
	shuffleStrings(candidates)

	var firstErr error
	for _, nodeURL := range candidates {
		if err := n.discoverFromNode(ctx, nodeURL); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			n.markNodeFailure(nodeURL, err)
			continue
		}
		if err := n.announceToNode(ctx, nodeURL); err != nil {
			n.log.Debug("discovery announce failed", "peer", nodeURL, "err", err)
		}
		n.touchKnownNode(nodeURL)
		n.adjustNodeScore(nodeURL, 1)
		n.log.Info("discovery contact ok", "peer", nodeURL)
		return nil
	}
	return firstErr
}

func (n *Node) runSyncRound(ctx context.Context) error {
	candidates := n.topSyncCandidateURLs(syncActivePeerLimit)
	if len(candidates) == 0 {
		n.log.Debug("sync round skipped", "reason", "no peer candidates")
		return nil
	}

	n.log.Debug("sync round starting", "candidates", len(candidates))
	var firstErr error
	for _, nodeURL := range candidates {
		if nodeURL == "" {
			continue
		}

		n.log.Debug("sync trying peer", "peer", nodeURL)

		// Fetch status once so we can inspect capabilities.
		// The result is also used inside syncCatchUp (it re-fetches),
		// but the extra round-trip only happens on multi-candidate failure;
		// in the common case the preflight merges into the same Tor circuit.
		status, err := n.fetchSyncStatus(ctx, nodeURL)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			n.markNodeFailure(nodeURL, err)
			n.log.Warn("sync status probe failed", "peer", nodeURL, "err", err)
			continue
		}

		var result syncAttemptResult
		if peerSupportsSync(status) {
			n.log.Debug("sync using sync_v1", "peer", nodeURL)
			result, err = n.syncCatchUp(ctx, nodeURL)
		} else {
			n.log.Debug("sync peer skipped", "peer", nodeURL, "capabilities", status.Capabilities)
			continue
		}

		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			n.markNodeFailure(nodeURL, err)
			n.log.Warn("sync peer failed", "peer", nodeURL)
			continue
		}

		if err := n.completeSyncAttempt(nodeURL, result, nil); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if result.importedTxCount > 0 {
			n.log.Info("sync imported txs", "count", result.importedTxCount, "peer", nodeURL)
		}
		return nil
	}

	return firstErr
}

type discoveryListResponse struct {
	Items []string `json:"items"`
	Page  listPage `json:"page"`
}

func (n *Node) discoverFromNode(ctx context.Context, nodeURL string) error {
	learned := 0
	announced := 0
	limit := discoveryMaxPageLimit
	afterScore := 0
	afterURL := ""
	hasAfter := false
	for {
		path := joinNodeURL(nodeURL, "/v1/discovery/nodes")
		if hasAfter {
			path += fmt.Sprintf("?limit=%d&after_peer_score=%d&after_peer_url=%s", limit, afterScore, url.QueryEscape(afterURL))
		} else {
			path += fmt.Sprintf("?limit=%d", limit)
		}
		var payload discoveryListResponse
		if err := n.getJSON(ctx, path, &payload); err != nil {
			return err
		}
		for _, discovered := range payload.Items {
			announced++
			if _, isNew, err := n.addKnownNode(discovered, false, true); err != nil {
				continue
			} else if isNew {
				learned++
			}
		}
		if !payload.Page.HasMore {
			break
		}
		afterPeer, ok := payload.Page.Next["after_peer"].(map[string]any)
		if !ok {
			break
		}
		score, _ := afterPeer["score"].(float64)
		afterURL, _ = afterPeer["url"].(string)
		afterScore = int(score)
		hasAfter = afterURL != ""
		if !hasAfter {
			break
		}
	}
	if announced > 0 {
		n.log.Info("discovery announced", "peer", nodeURL, "announced", announced, "learned", learned)
	}
	return nil
}
func (n *Node) announceToNode(ctx context.Context, nodeURL string) error {
	addresses := n.advertisedAddresses()
	if len(addresses) == 0 {
		return nil
	}
	request := discoveryAnnounceRequest{Addresses: addresses}
	return n.postJSON(ctx, joinNodeURL(nodeURL, "/v1/discovery/announce"), request, relayContext{})
}
