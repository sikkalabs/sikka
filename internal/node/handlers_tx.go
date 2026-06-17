package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"besoeasy/sikka/internal/chain"
)

func (n *Node) handleTxWeight(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	if n.dag.GetTransaction(txid) == nil {
		http.NotFound(w, r)
		return
	}
	weight := n.dag.TxWeight(txid)
	confirmed := n.dag.IsConfirmed(txid)
	n.writeJSON(w, http.StatusOK, map[string]any{
		"txid":      txid,
		"weight":    weight,
		"confirmed": confirmed,
	})
}

func (n *Node) handleDiscoveryNodes(w http.ResponseWriter, r *http.Request) {
	limit := discoveryDefaultPageLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		parsed, err := parseNonNegativeInt(q)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid limit"))
			return
		}
		if parsed > 0 {
			limit = parsed
		}
	}
	limit = clampLimit(limit, discoveryDefaultPageLimit, discoveryMaxPageLimit)

	afterScore := 0
	afterURL := ""
	hasAfter := false
	if q := r.URL.Query().Get("after_peer_score"); q != "" || r.URL.Query().Get("after_peer_url") != "" {
		scoreRaw := strings.TrimSpace(r.URL.Query().Get("after_peer_score"))
		afterURL = strings.TrimSpace(r.URL.Query().Get("after_peer_url"))
		if scoreRaw == "" || afterURL == "" {
			n.writeRequestError(w, fmt.Errorf("after_peer requires both after_peer_score and after_peer_url"))
			return
		}
		score, err := strconv.Atoi(scoreRaw)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid after_peer_score"))
			return
		}
		afterScore = score
		hasAfter = true
	}

	peers, hasMore, next, err := pageDiscoveryPeerEntries(n.discoveryPeerEntries(), limit, afterScore, afterURL, hasAfter)
	if err != nil {
		n.writeRequestError(w, err)
		return
	}
	if peers == nil {
		peers = []string{}
	}
	n.writeListResponse(w, peers, limit, hasMore, next, nil)
}

func (n *Node) handleDiscoveryAnnounce(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var payload discoveryAnnounceRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		n.writeRequestError(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	if len(payload.Addresses) == 0 {
		n.writeRequestError(w, fmt.Errorf("addresses are required"))
		return
	}
	if len(payload.Addresses) > maxAnnouncedAddresses {
		n.writeRequestError(w, fmt.Errorf("too many addresses: max %d", maxAnnouncedAddresses))
		return
	}
	validatedAddresses, err := n.validateAnnouncedPeer(r.Context(), payload.Addresses)
	if err != nil {
		n.writeRequestError(w, err)
		return
	}
	if len(validatedAddresses) == 0 {
		n.writeJSON(w, http.StatusOK, map[string]any{
			"status":           "ignored",
			"known_node_count": n.knownNodeCount(),
		})
		return
	}
	_, accepted, err := n.addKnownPeer(validatedAddresses, false, true)
	if err != nil {
		n.writeRequestError(w, err)
		return
	}
	status := "accepted"
	if !accepted {
		status = "ignored"
	}
	n.writeJSON(w, http.StatusOK, map[string]any{
		"status":           status,
		"known_node_count": n.knownNodeCount(),
	})
}

func (n *Node) handleTxLookup(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	tx := n.dag.GetTransaction(txid)
	if tx == nil {
		http.NotFound(w, r)
		return
	}
	n.writeJSON(w, http.StatusOK, tx)
}

func (n *Node) handleTxsBulkLookup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var txIDs []string
	if err := json.NewDecoder(r.Body).Decode(&txIDs); err != nil {
		n.writeRequestError(w, fmt.Errorf("invalid request body"))
		return
	}
	if len(txIDs) > maxBulkTxLookupIDs {
		n.writeRequestError(w, fmt.Errorf("too many IDs requested: max %d", maxBulkTxLookupIDs))
		return
	}
	var txs []*chain.Transaction
	for _, id := range txIDs {
		tx := n.dag.GetTransaction(id)
		if tx != nil {
			txs = append(txs, tx)
		}
	}
	if txs == nil {
		txs = []*chain.Transaction{}
	}
	n.writeListResponse(w, txs, len(txIDs), false, nil, map[string]any{
		"requested": len(txIDs),
		"found":     len(txs),
	})
}

func (n *Node) handleAddress(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		n.writeRequestError(w, fmt.Errorf("missing address"))
		return
	}
	limit := defaultAddressUTXOLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		parsed, err := parseNonNegativeInt(q)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid limit"))
			return
		}
		if parsed > 0 {
			limit = parsed
		}
	}
	limit = clampLimit(limit, defaultAddressUTXOLimit, maxAddressUTXOLimit)

	afterTxID, afterIndex, _, err := parseAfterOutpointQuery(r)
	if err != nil {
		n.writeRequestError(w, err)
		return
	}

	allUTXOs := n.dag.GetUTXOs(address)
	if allUTXOs == nil {
		allUTXOs = []*chain.UTXO{}
	}
	balance := int64(0)
	for _, utxo := range allUTXOs {
		if utxo == nil {
			continue
		}
		balance += utxo.Value
	}

	pageItems, hasMore, next, err := pageUTXOs(allUTXOs, limit, afterTxID, afterIndex)
	if err != nil {
		n.writeRequestError(w, err)
		return
	}
	if pageItems == nil {
		pageItems = []*chain.UTXO{}
	}
	n.writeListResponse(w, pageItems, limit, hasMore, next, map[string]any{
		"address":    address,
		"balance":    balance,
		"utxo_count": len(allUTXOs),
	})
}

func (n *Node) handleTxPowQuote(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var payload struct {
		Parents   []string `json:"parents"`
		Timestamp int64    `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		n.writeRequestError(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	quote, err := n.dag.QuoteTxPoW(&chain.Transaction{Parents: payload.Parents, Timestamp: payload.Timestamp})
	if err != nil {
		n.writeRequestError(w, err)
		return
	}
	n.writeJSON(w, http.StatusOK, quote)
}

func (n *Node) handleTxSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var tx chain.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		n.writeRequestError(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	if err := n.dag.SubmitTx(&tx); err != nil {
		n.writeRequestError(w, err)
		return
	}
	n.enqueueRelayTransaction(&tx, relayContextFromRequest(r))
	n.writeJSON(w, http.StatusOK, map[string]string{
		"txid":   tx.ID,
		"status": "accepted",
	})
}
