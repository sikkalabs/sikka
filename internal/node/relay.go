package node

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"besoeasy/sikka/internal/chain"
)

func relayContextFromRequest(r *http.Request) relayContext {
	if r == nil {
		return relayContext{}
	}
	hop := 0
	if raw := strings.TrimSpace(r.Header.Get(relayHeaderHop)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			hop = parsed
		}
	}
	return relayContext{
		origin: strings.TrimSpace(r.Header.Get(relayHeaderOrigin)),
		sender: strings.TrimSpace(r.Header.Get(relayHeaderSender)),
		hop:    hop,
	}
}

func (n *Node) enqueueRelayTransaction(tx *chain.Transaction, relay relayContext) {
	if tx == nil || !n.shouldRelay(relay) {
		return
	}
	cloned := *tx
	go n.relayTransaction(context.Background(), &cloned, relay)
}

func (n *Node) shouldRelay(relay relayContext) bool {
	return relay.hop < relayMaxHops
}

func (n *Node) relayTransaction(ctx context.Context, tx *chain.Transaction, relay relayContext) {
	n.relayJSON(ctx, "/v1/tx/submit", tx, relay)
}

func (n *Node) relayJSON(ctx context.Context, path string, payload any, relay relayContext) {
	nextRelay := n.nextRelayContext(relay)
	for _, nodeURL := range n.relayTargets(nextRelay) {
		if err := n.postJSON(ctx, joinNodeURL(nodeURL, path), payload, nextRelay); err != nil {
			n.log.Warn("relay failed", "path", path, "peer", nodeURL, "err", err)
			n.markNodeFailure(nodeURL, err)
			continue
		}
		n.touchKnownNode(nodeURL)
	}
}

func (n *Node) nextRelayContext(relay relayContext) relayContext {
	self := strings.TrimSpace(n.onionPublicURL)
	next := relayContext{
		origin: relay.origin,
		sender: self,
		hop:    relay.hop + 1,
	}
	if next.origin == "" {
		next.origin = self
	}
	return next
}

func (n *Node) relayTargets(relay relayContext) []string {
	excluded := make(map[string]bool)
	if self := strings.TrimSpace(n.onionPublicURL); self != "" {
		excluded[self] = true
	}
	if relay.origin != "" {
		excluded[relay.origin] = true
	}
	if relay.sender != "" {
		excluded[relay.sender] = true
	}
	candidates := n.availableNodeURLs(relayFanout)
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if excluded[candidate] {
			continue
		}
		out = append(out, candidate)
	}
	return out
}
