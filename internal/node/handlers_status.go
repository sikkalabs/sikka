package node

import (
	"net/http"
	"strings"
	"time"

	"besoeasy/sikka"
	"besoeasy/sikka/internal/chain"
)

func (n *Node) handleHealth(w http.ResponseWriter, _ *http.Request) {
	n.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (n *Node) nodeAddressDisplay() string {
	return strings.TrimSpace(n.config.NodeAddress)
}

func (n *Node) nodeMessageDisplay() string {
	if strings.TrimSpace(n.config.NodeMessage) != "" {
		return n.config.NodeMessage
	}
	return "SIKKA " + sikka.CurrentRelease().SoftwareVersion
}

func (n *Node) handleStatus(w http.ResponseWriter, _ *http.Request) {
	release := sikka.CurrentRelease()
	lastSyncAt, lastSyncSource, lastSyncError := n.syncSnapshot()
	lastSync := ""
	if !lastSyncAt.IsZero() {
		lastSync = lastSyncAt.UTC().Format(time.RFC3339)
	}
	tips := n.localSyncDAGTips()
	payload := map[string]any{
		"addresses":                     n.advertisedAddresses(),
		"software_version":              release.SoftwareVersion,
		"node_address":                  n.nodeAddressDisplay(),
		"node_message":                  n.nodeMessageDisplay(),
		"protocol_version":              release.ProtocolVersion,
		"capabilities":                  release.Capabilities,
		"api_listen":                    n.config.APIListenAddress(),
		"known_node_count":              n.knownNodeCount(),
		"configured_nodes":              n.config.SyncSeeds,
		"sync_interval_s":               n.config.SyncIntervalSeconds,
		"last_sync_at":                  lastSync,
		"last_sync_source":              lastSyncSource,
		"last_sync_error":               lastSyncError,
		"dag_size":                      n.dag.Size(),
		"genesis_tx_id":                 n.dag.GenesisID(),
		"tip_count":                     len(tips),
		"tips":                          tips,
		"max_dag_depth":                 n.dag.MaxDepth(),
		"submit_pow_base_bits":          chain.BaseTxWorkBits,
		"submit_pow_window_seconds":     chain.PowCongestionWindowSeconds,
		"submit_pow_target_tps":         chain.PowTargetTransactionsPerSecond,
		"submit_pow_bucket_tx":          chain.PowCongestionBucketTransactions,
		"submit_pow_bucket_bits":        chain.PowCongestionBucketBits,
		"submit_pow_bucket_work_factor": 1 << chain.PowCongestionBucketBits,
		"max_future_skew_seconds":       chain.MaxFutureSkewSeconds,
		"conflict_prune_grace_seconds":  chain.ConflictPruneGraceSeconds,
		"data_dir":                      n.config.DataDir,
		"total_supply":                  chain.TotalSupply,
	}
	if override := n.dag.MinPowBitsOverride(); override > 0 {
		payload["submit_pow_override_bits"] = override
	}
	for key, value := range n.torStatusPayload() {
		payload[key] = value
	}
	n.writeJSON(w, http.StatusOK, payload)
}

func (n *Node) torStatusPayload() map[string]any {
	hostname := strings.TrimPrefix(strings.TrimSpace(n.onionPublicURL), "http://")

	payload := map[string]any{
		"enabled":             true,
		"mode":                "managed",
		"onion_hostname":      hostname,
		"addresses":           n.advertisedAddresses(),
		"control_connected":   false,
		"network_health":      "unavailable",
		"bootstrap_progress":  0,
		"bootstrap_tag":       "",
		"bootstrap_summary":   "",
		"bootstrap_warning":   "",
		"circuit_established": false,
		"control_error":       "",
	}

	control := n.currentTorControl()
	if control == nil {
		return payload
	}

	payload["control_connected"] = true
	health, err := control.networkHealth()
	if err != nil {
		payload["network_health"] = "degraded"
		payload["control_error"] = err.Error()
		return payload
	}

	payload["network_health"] = health.NetworkHealth
	payload["bootstrap_progress"] = health.BootstrapProgress
	payload["bootstrap_tag"] = health.BootstrapTag
	payload["bootstrap_summary"] = health.BootstrapSummary
	payload["bootstrap_warning"] = health.BootstrapWarning
	payload["circuit_established"] = health.CircuitEstablished
	return payload
}

func (n *Node) handleSyncStatus(w http.ResponseWriter, _ *http.Request) {
	release := sikka.CurrentRelease()
	localSummary := n.localSyncDAGSummary()
	n.writeJSON(w, http.StatusOK, map[string]any{
		"addresses":        n.advertisedAddresses(),
		"software_version": release.SoftwareVersion,
		"node_address":     n.nodeAddressDisplay(),
		"node_message":     n.nodeMessageDisplay(),
		"protocol_version": release.ProtocolVersion,
		"capabilities":     release.Capabilities,
		"configured_nodes": n.config.SyncSeeds,
		"known_node_count": n.knownNodeCount(),
		"dag_size":         localSummary.DAGSize,
		"tip_count":        localSummary.TipCount,
		"max_dag_depth":    localSummary.MaxDAGDepth,
		"tips_fingerprint": localSummary.TipsFingerprint,
		"genesis_tx_id":    n.dag.GenesisID(),
		"order":            syncOrderVersion,
	})
}

type dagTipsResponse struct {
	Tips            []string `json:"tips"`
	TipCount        int      `json:"tip_count"`
	MaxDAGDepth     int64    `json:"max_dag_depth"`
	TipsFingerprint string   `json:"tips_fingerprint"`
}

func (n *Node) handleDAGTips(w http.ResponseWriter, _ *http.Request) {
	summary := n.localSyncDAGSummary()
	tips := n.dag.Tips()
	n.writeJSON(w, http.StatusOK, dagTipsResponse{
		Tips:            tips,
		TipCount:        summary.TipCount,
		MaxDAGDepth:     summary.MaxDAGDepth,
		TipsFingerprint: summary.TipsFingerprint,
	})
}

type peerTelemetryItem struct {
	Address     string     `json:"address"`
	Score       int        `json:"score"`
	LatencyMs   int64      `json:"latency_ms"`
	LastSeen    time.Time  `json:"last_seen"`
	LastSync    time.Time  `json:"last_sync,omitempty"`
	Bootstrap   bool       `json:"bootstrap"`
	Banned      bool       `json:"banned"`
	BannedUntil *time.Time `json:"banned_until,omitempty"`
	BanReason   string     `json:"ban_reason,omitempty"`
}

type peerTelemetryResponse struct {
	Peers       []peerTelemetryItem `json:"peers"`
	TotalKnown  int                 `json:"total_known"`
	BannedCount int                 `json:"banned_count"`
}

func (n *Node) handlePeers(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	n.nodeBookMu.RLock()
	peers := make([]peerTelemetryItem, 0, len(n.knownNodes))
	bannedCount := 0

	for _, record := range n.knownNodes {
		if record == nil || shouldPruneNode(record, now) {
			continue
		}
		addr := n.selectPeerAddress(record, now, false)
		if addr == "" {
			continue
		}
		state := record.addresses[addr]
		latencyMs := int64(0)
		if state != nil && state.latencyEMA > 0 {
			latencyMs = state.latencyEMA.Milliseconds()
		}
		isBanned := !record.bannedUntil.IsZero() && now.Before(record.bannedUntil)
		var bannedUntilPtr *time.Time
		if isBanned {
			bannedCount++
			bannedUntilPtr = &record.bannedUntil
		}

		item := peerTelemetryItem{
			Address:     addr,
			Score:       record.score,
			LatencyMs:   latencyMs,
			LastSeen:    record.lastSeen,
			LastSync:    record.lastSync,
			Bootstrap:   record.bootstrap,
			Banned:      isBanned,
			BannedUntil: bannedUntilPtr,
			BanReason:   record.banReason,
		}
		peers = append(peers, item)
	}
	n.nodeBookMu.RUnlock()

	n.writeJSON(w, http.StatusOK, peerTelemetryResponse{
		Peers:       peers,
		TotalKnown:  len(peers),
		BannedCount: bannedCount,
	})
}

type addressHistoryResponse struct {
	Address      string              `json:"address"`
	Transactions []chain.Transaction `json:"transactions"`
	Count        int                 `json:"count"`
}

func (n *Node) handleAddressHistory(w http.ResponseWriter, r *http.Request) {
	rawAddress := r.PathValue("address")
	normalized, err := chain.NormalizeAddress(rawAddress)
	if err != nil {
		n.writeErrorResponse(w, http.StatusBadRequest, "invalid_address", err.Error())
		return
	}
	txs := n.dag.GetAddressTransactions(normalized)
	n.writeJSON(w, http.StatusOK, addressHistoryResponse{
		Address:      normalized,
		Transactions: txs,
		Count:        len(txs),
	})
}
