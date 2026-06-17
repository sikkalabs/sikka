package node

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"besoeasy/sikka/internal/chain"
)

const (
	defaultSyncTailLimit      = 100
	maxSyncTailLimit          = 2000
	discoveryDefaultPageLimit = 32
	discoveryMaxPageLimit     = 64
	defaultAddressUTXOLimit   = 100
	maxAddressUTXOLimit       = 500
)

type listPage struct {
	Limit   int            `json:"limit"`
	HasMore bool           `json:"has_more"`
	Next    map[string]any `json:"next,omitempty"`
}

type listEnvelope struct {
	Items any            `json:"items"`
	Page  listPage       `json:"page"`
	Meta  map[string]any `json:"meta,omitempty"`
}

type discoveryPeerEntry struct {
	score int
	url   string
}

func (n *Node) discoveryPeerEntries() []discoveryPeerEntry {
	now := time.Now()
	records := n.scoredNodeRecords(0, true)

	entries := make([]discoveryPeerEntry, 0, len(records)+1)
	selfURL := ""
	if selfAddresses := n.advertisedAddresses(); len(selfAddresses) > 0 {
		selfURL = selfAddresses[0]
		entries = append(entries, discoveryPeerEntry{score: math.MaxInt32, url: selfURL})
	}

	for _, record := range records {
		address := n.selectPeerAddress(record, now, true)
		if address == "" || address == selfURL {
			continue
		}
		entries = append(entries, discoveryPeerEntry{score: record.score, url: address})
	}
	return entries
}

func pageDiscoveryPeerEntries(entries []discoveryPeerEntry, limit int, afterScore int, afterURL string, hasAfter bool) ([]string, bool, map[string]any, error) {
	start := 0
	if hasAfter {
		found := false
		for i, entry := range entries {
			if entry.score == afterScore && entry.url == afterURL {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, false, nil, fmt.Errorf("unknown after_peer resume key")
		}
	}

	end := start + limit
	hasMore := end < len(entries)
	if end > len(entries) {
		end = len(entries)
	}

	page := entries[start:end]
	peers := make([]string, len(page))
	for i, entry := range page {
		peers[i] = entry.url
	}

	var next map[string]any
	if hasMore && len(page) > 0 {
		last := page[len(page)-1]
		next = map[string]any{
			"after_peer": map[string]any{
				"score": last.score,
				"url":   last.url,
			},
		}
	}
	return peers, hasMore, next, nil
}

func parseAfterOutpointQuery(r *http.Request) (afterTxID string, afterIndex int, hasAfter bool, err error) {
	txid := strings.TrimSpace(r.URL.Query().Get("after_outpoint_txid"))
	indexRaw := strings.TrimSpace(r.URL.Query().Get("after_outpoint_index"))
	if txid == "" && indexRaw == "" {
		return "", 0, false, nil
	}
	if txid == "" || indexRaw == "" {
		return "", 0, false, fmt.Errorf("after_outpoint requires both after_outpoint_txid and after_outpoint_index")
	}
	parsed, err := parseNonNegativeInt(indexRaw)
	if err != nil {
		return "", 0, false, fmt.Errorf("invalid after_outpoint_index")
	}
	return txid, parsed, true, nil
}

func pageUTXOs(allUTXOs []*chain.UTXO, limit int, afterTxID string, afterIndex int) ([]*chain.UTXO, bool, map[string]any, error) {
	start := 0
	if afterTxID != "" {
		found := false
		for i, utxo := range allUTXOs {
			if utxo != nil && utxo.TxID == afterTxID && utxo.Index == afterIndex {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, false, nil, fmt.Errorf("unknown after_outpoint resume key")
		}
	}

	end := start + limit
	hasMore := end < len(allUTXOs)
	if end > len(allUTXOs) {
		end = len(allUTXOs)
	}

	pageItems := append([]*chain.UTXO(nil), allUTXOs[start:end]...)

	var next map[string]any
	if hasMore && len(pageItems) > 0 {
		last := pageItems[len(pageItems)-1]
		next = map[string]any{
			"after_outpoint": map[string]any{
				"txid":  last.TxID,
				"index": last.Index,
			},
		}
	}
	return pageItems, hasMore, next, nil
}

func (n *Node) writeListResponse(w http.ResponseWriter, items any, limit int, hasMore bool, next map[string]any, meta map[string]any) {
	page := listPage{
		Limit:   limit,
		HasMore: hasMore,
	}
	if hasMore && len(next) > 0 {
		page.Next = next
	}
	resp := map[string]any{
		"items": items,
		"page":  page,
	}
	if meta != nil {
		resp["meta"] = meta
	}
	n.writeJSON(w, http.StatusOK, resp)
}

func parseNonNegativeInt(raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("invalid non-negative integer")
	}
	return value, nil
}

func clampLimit(limit, defaultVal, maxVal int) int {
	if limit <= 0 {
		return defaultVal
	}
	if limit > maxVal {
		return maxVal
	}
	return limit
}
