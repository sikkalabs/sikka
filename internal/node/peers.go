package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (n *Node) knownNodeCount() int {
	n.nodeBookMu.RLock()
	defer n.nodeBookMu.RUnlock()
	return len(n.knownNodes)
}

func (n *Node) knownNodeURLs(limit int) []string {
	return n.nodeURLs(limit, false)
}

func (n *Node) availableNodeURLs(limit int) []string {
	return n.nodeURLs(limit, true)
}

func (n *Node) nodeURLs(limit int, availableOnly bool) []string {
	now := time.Now()
	records := n.nodeRecords(limit, availableOnly)
	out := make([]string, 0, len(records))
	for _, record := range records {
		if address := n.selectPeerAddress(record, now, availableOnly); address != "" {
			out = append(out, address)
		}
	}
	return out
}

func (n *Node) nodeRecords(limit int, availableOnly bool) []*nodeRecord {
	now := time.Now()
	n.nodeBookMu.RLock()
	records := make([]*nodeRecord, 0, len(n.knownNodes))
	for _, record := range n.knownNodes {
		if record == nil || shouldPruneNode(record, now) {
			continue
		}
		if availableOnly && n.selectPeerAddress(record, now, true) == "" {
			continue
		}
		records = append(records, record)
	}
	n.nodeBookMu.RUnlock()
	sort.Slice(records, func(i, j int) bool {
		if records[i].bootstrap != records[j].bootstrap {
			return records[i].bootstrap
		}
		if records[i].lastSeen.Equal(records[j].lastSeen) {
			return nodeRecordSortKey(records[i]) < nodeRecordSortKey(records[j])
		}
		return records[i].lastSeen.After(records[j].lastSeen)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records
}

func nodeRecordSortKey(record *nodeRecord) string {
	if record == nil {
		return ""
	}
	addresses := recordAddressURLs(record)
	if len(addresses) == 0 {
		return ""
	}
	return addresses[0]
}

func recordAddressURLs(record *nodeRecord) []string {
	if record == nil || len(record.addresses) == 0 {
		return nil
	}
	addresses := make([]string, 0, len(record.addresses))
	for address := range record.addresses {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses
}

func (n *Node) selectPeerAddress(record *nodeRecord, now time.Time, availableOnly bool) string {
	addresses := recordAddressURLs(record)
	if len(addresses) == 0 {
		return ""
	}
	sort.SliceStable(addresses, func(i, j int) bool {
		return n.compareAddressPreference(addresses[i], addresses[j]) < 0
	})
	for _, address := range addresses {
		state := record.addresses[address]
		if availableOnly && isNodeCoolingDown(state, now) {
			continue
		}
		return address
	}
	return ""
}

func (n *Node) compareAddressPreference(left, right string) int {
	leftOnion := isOnionNodeURL(left)
	rightOnion := isOnionNodeURL(right)
	if leftOnion != rightOnion {
		if leftOnion {
			return -1
		}
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func (n *Node) adjustNodeScore(nodeURL string, delta int) {
	normalized, err := normalizeDiscoveredNodeURL(nodeURL)
	if err != nil {
		return
	}
	n.nodeBookMu.Lock()
	defer n.nodeBookMu.Unlock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	if record == nil {
		return
	}
	record.score += delta
}

func (n *Node) setNodeLastSync(nodeURL string, at time.Time) {
	normalized, err := normalizeDiscoveredNodeURL(nodeURL)
	if err != nil {
		return
	}
	n.nodeBookMu.Lock()
	defer n.nodeBookMu.Unlock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	if record == nil {
		return
	}
	record.lastSync = at
}

func (n *Node) updatePeerLastMatched(nodeURL string, matchedSize int) {
	if matchedSize <= 0 {
		return
	}
	normalized, err := normalizeDiscoveredNodeURL(nodeURL)
	if err != nil {
		return
	}
	n.nodeBookMu.Lock()
	defer n.nodeBookMu.Unlock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	if record == nil {
		return
	}
	if matchedSize > record.lastMatchedSize {
		record.lastMatchedSize = matchedSize
	}
}

func (n *Node) topSyncCandidateURLs(limit int) []string {
	now := time.Now()
	records := n.scoredNodeRecords(limit, true)
	out := make([]string, 0, len(records))
	for _, record := range records {
		if address := n.selectPeerAddress(record, now, true); address != "" {
			out = append(out, address)
		}
	}
	return out
}

func (n *Node) scoredNodeRecords(limit int, availableOnly bool) []*nodeRecord {
	now := time.Now()
	n.nodeBookMu.RLock()
	records := make([]*nodeRecord, 0, len(n.knownNodes))
	for _, record := range n.knownNodes {
		if record == nil || shouldPruneNode(record, now) {
			continue
		}
		if availableOnly && n.selectPeerAddress(record, now, true) == "" {
			continue
		}
		records = append(records, record)
	}
	n.nodeBookMu.RUnlock()
	sort.Slice(records, func(i, j int) bool {
		if records[i].score != records[j].score {
			return records[i].score > records[j].score
		}
		if records[i].lastSeen.Equal(records[j].lastSeen) {
			return nodeRecordSortKey(records[i]) < nodeRecordSortKey(records[j])
		}
		return records[i].lastSeen.After(records[j].lastSeen)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records
}

func (n *Node) addKnownNode(rawURL string, bootstrap bool, persist bool) (string, bool, error) {
	return n.addKnownPeer([]string{rawURL}, bootstrap, persist)
}

func (n *Node) addKnownPeer(rawAddresses []string, bootstrap bool, persist bool) (string, bool, error) {
	normalizedAddresses, err := n.normalizePeerAddresses(rawAddresses)
	if err != nil {
		return "", false, err
	}
	if len(normalizedAddresses) == 0 {
		return "", false, nil
	}

	now := time.Now()
	shouldPersist := false
	addedNew := false
	n.nodeBookMu.Lock()

	recordKey := peerRecordKey(normalizedAddresses[0])
	record := n.knownNodes[recordKey]
	if record == nil {
		for _, address := range normalizedAddresses {
			if existingKey, existingRecord, _ := n.findKnownNodeByAddressLocked(address); existingRecord != nil {
				recordKey = existingKey
				record = existingRecord
				break
			}
		}
	}
	if record == nil {
		// Enforce the cap only for new nodes, not for updates to existing ones.
		if len(n.knownNodes) >= maxKnownNodes {
			n.nodeBookMu.Unlock()
			return "", false, nil
		}
		record = &nodeRecord{bootstrap: bootstrap, score: nodeInitialScore, lastSeen: now, addresses: make(map[string]*addressRecord)}
		n.knownNodes[recordKey] = record
		shouldPersist = persist && !bootstrap
		addedNew = true
		if !bootstrap {
			n.log.Info("peer learned", "url", normalizedAddresses[0])
		}
	} else {
		if record.addresses == nil {
			record.addresses = make(map[string]*addressRecord)
		}
		if bootstrap {
			record.bootstrap = true
		}
		record.lastSeen = now
	}

	for _, address := range normalizedAddresses {
		state := record.addresses[address]
		if state == nil {
			state = &addressRecord{url: address}
			record.addresses[address] = state
		}
		state.lastSeen = now
	}
	n.nodeBookMu.Unlock()
	if shouldPersist {
		if err := n.persistNodeBook(); err != nil {
			n.log.Error("persist nodebook after peer update", "err", err)
		}
	}
	return recordKey, addedNew, nil
}

func peerRecordKey(address string) string {
	return "addr:" + strings.TrimSpace(address)
}

func (n *Node) normalizePeerAddresses(rawAddresses []string) ([]string, error) {
	seen := make(map[string]bool, len(rawAddresses))
	normalized := make([]string, 0, len(rawAddresses))
	selfAddresses := make(map[string]bool, len(n.advertisedAddresses()))
	for _, address := range n.advertisedAddresses() {
		selfAddresses[address] = true
	}
	for _, raw := range rawAddresses {
		candidate, err := normalizeDiscoveredNodeURL(raw)
		if err != nil {
			return nil, err
		}
		if selfAddresses[candidate] || seen[candidate] {
			continue
		}
		seen[candidate] = true
		normalized = append(normalized, candidate)
	}
	return normalized, nil
}

func (n *Node) findKnownNodeByAddressLocked(address string) (string, *nodeRecord, *addressRecord) {
	for key, record := range n.knownNodes {
		if record == nil {
			continue
		}
		if state := record.addresses[address]; state != nil {
			return key, record, state
		}
	}
	return "", nil, nil
}

func (n *Node) markNodeFailure(nodeURL string, failure error) {
	normalized, err := normalizeDiscoveredNodeURL(nodeURL)
	if err != nil {
		return
	}
	reason := describeNodeFailure(normalized, failure)
	n.nodeBookMu.Lock()
	key, record, addressState := n.findKnownNodeByAddressLocked(normalized)
	if record == nil {
		key = peerRecordKey(normalized)
		record = &nodeRecord{score: nodeInitialScore, lastSeen: time.Now(), addresses: make(map[string]*addressRecord)}
		addressState = &addressRecord{url: normalized, lastSeen: record.lastSeen}
		record.addresses[normalized] = addressState
		n.knownNodes[key] = record
	}
	now := time.Now()
	record.score--
	addressState.failureCount++
	addressState.lastFailed = now
	addressState.nextRetryAt = now.Add(nextNodeRetryDelay(addressState.failureCount))
	n.nodeBookMu.Unlock()
	retryAfter := time.Until(addressState.nextRetryAt).Round(time.Second)
	if retryAfter < 0 {
		retryAfter = 0
	}
	evictAfter := nodeStaleAfter
	if !record.lastSeen.IsZero() {
		remaining := nodeStaleAfter - now.Sub(record.lastSeen)
		if remaining > 0 {
			evictAfter = remaining.Round(time.Second)
		} else {
			evictAfter = 0
		}
	}
	n.log.Warn("peer failure",
		"url", normalized,
		"reason", reason,
		"retry_after", retryAfter,
		"evict_after", evictAfter,
		"err", failure,
	)
	if err := n.persistNodeBook(); err != nil {
		n.log.Error("persist nodebook after peer failure", "err", err)
	}
}

func describeNodeFailure(nodeURL string, failure error) string {
	if failure == nil {
		return "request failed"
	}
	message := strings.ToLower(failure.Error())
	switch {
	case strings.Contains(message, "protocol mismatch"):
		return "peer is running an incompatible protocol version"
	case strings.Contains(message, "genesis mismatch"):
		return "peer is on a different network"
	case strings.Contains(message, "does not support sync_v1"):
		return "peer does not support current sync_v1 (old software)"
	case strings.Contains(nodeURL, ".onion") && (strings.Contains(message, "deadline exceeded") || strings.Contains(message, "timeout")):
		return "onion peer is unreachable or offline"
	case strings.Contains(nodeURL, ".onion"):
		return "onion peer request failed"
	default:
		return "peer request failed"
	}
}

func (n *Node) touchKnownNode(nodeURL string) {
	normalized, err := normalizeDiscoveredNodeURL(nodeURL)
	if err != nil {
		return
	}
	n.nodeBookMu.Lock()
	defer n.nodeBookMu.Unlock()
	_, record, state := n.findKnownNodeByAddressLocked(normalized)
	if record != nil && state != nil {
		now := time.Now()
		record.lastSeen = now
		state.lastSeen = now
		state.lastFailed = time.Time{}
		state.failureCount = 0
		state.nextRetryAt = time.Time{}
	}
}

func (n *Node) recordSyncSuccess(nodeURL string) {
	n.syncStateMu.Lock()
	defer n.syncStateMu.Unlock()
	n.lastSyncAt = time.Now()
	n.lastSyncSource = nodeURL
	n.lastSyncError = ""
}

func (n *Node) recordSyncFailure(nodeURL string, err error) {
	if err == nil {
		return
	}
	n.syncStateMu.Lock()
	defer n.syncStateMu.Unlock()
	if nodeURL != "" {
		n.lastSyncSource = nodeURL
	}
	n.lastSyncError = err.Error()
}

func (n *Node) syncSnapshot() (time.Time, string, string) {
	n.syncStateMu.RLock()
	defer n.syncStateMu.RUnlock()
	return n.lastSyncAt, n.lastSyncSource, n.lastSyncError
}

func (n *Node) nodeBookPath() string {
	return filepath.Join(n.config.DataDir, nodeBookFileName)
}

func (n *Node) loadNodeBook() error {
	payload, err := os.ReadFile(n.nodeBookPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var stored persistedNodeBook
	if err := json.Unmarshal(payload, &stored); err != nil {
		return err
	}
	now := time.Now()
	n.nodeBookMu.Lock()
	defer n.nodeBookMu.Unlock()
	for _, persisted := range stored.Nodes {
		normalizedAddresses := make([]string, 0, len(persisted.Addresses))
		for _, address := range persisted.Addresses {
			normalized, err := normalizeDiscoveredNodeURL(address)
			if err != nil {
				continue
			}
			normalizedAddresses = append(normalizedAddresses, normalized)
		}
		if len(normalizedAddresses) == 0 {
			continue
		}
		record := &nodeRecord{score: nodeInitialScore, lastSeen: persisted.LastSeen, addresses: make(map[string]*addressRecord, len(normalizedAddresses)), lastMatchedSize: persisted.LastMatchedSize}
		if record.lastSeen.IsZero() {
			record.lastSeen = now
		}
		if shouldPruneNode(record, now) {
			continue
		}
		for _, address := range normalizedAddresses {
			record.addresses[address] = &addressRecord{url: address, lastSeen: record.lastSeen}
		}
		key := peerRecordKey(normalizedAddresses[0])
		if n.knownNodes[key] == nil {
			n.knownNodes[key] = record
		}
	}
	return nil
}

func (n *Node) persistNodeBook() error {
	stored := persistedNodeBook{Nodes: n.persistableNodes()}
	payload, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(n.nodeBookPath()), "nodebook.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()
	defer os.Remove(tmpPath)
	return os.Rename(tmpPath, n.nodeBookPath())
}

func (n *Node) persistableNodes() []persistedNode {
	n.nodeBookMu.RLock()
	defer n.nodeBookMu.RUnlock()
	now := time.Now()
	nodes := make([]persistedNode, 0, len(n.knownNodes))
	for _, record := range n.knownNodes {
		if record == nil || record.bootstrap || shouldPruneNode(record, now) {
			continue
		}
		addresses := recordAddressURLs(record)
		if len(addresses) == 0 {
			continue
		}
		nodes = append(nodes, persistedNode{Addresses: addresses, LastSeen: record.lastSeen, LastMatchedSize: record.lastMatchedSize})
	}
	sort.Slice(nodes, func(i, j int) bool {
		left := ""
		if len(nodes[i].Addresses) > 0 {
			left = nodes[i].Addresses[0]
		}
		right := ""
		if len(nodes[j].Addresses) > 0 {
			right = nodes[j].Addresses[0]
		}
		return left < right
	})
	return nodes
}
func (n *Node) pruneKnownNodes(now time.Time) int {
	n.nodeBookMu.Lock()
	removed := 0
	for key, record := range n.knownNodes {
		if record == nil || record.bootstrap {
			continue
		}
		if !shouldPruneNode(record, now) {
			continue
		}
		delete(n.knownNodes, key)
		removed++
	}
	n.nodeBookMu.Unlock()
	if removed > 0 {
		if err := n.persistNodeBook(); err != nil {
			n.log.Error("persist nodebook after prune", "err", err)
		}
	}
	return removed
}

func shouldPruneNode(record *nodeRecord, now time.Time) bool {
	if record == nil {
		return false
	}
	if record.bootstrap {
		return false
	}
	if record.lastSeen.IsZero() {
		return true
	}
	return now.Sub(record.lastSeen) >= nodeStaleAfter
}

func isNodeCoolingDown(address *addressRecord, now time.Time) bool {
	if address == nil {
		return false
	}
	return !address.nextRetryAt.IsZero() && now.Before(address.nextRetryAt)
}
