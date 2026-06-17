package node

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"besoeasy/sikka/internal/chain"

	"golang.org/x/crypto/sha3"
)

func (n *Node) handleSyncTail(w http.ResponseWriter, r *http.Request) {
	var req syncTailRequest

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid body: %w", err))
			return
		}
	}
	limit := defaultSyncTailLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		parsed, err := parseNonNegativeInt(q)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid limit"))
			return
		}
		if parsed > 0 {
			limit = parsed
		}
	} else if req.Limit > 0 {
		limit = req.Limit
	}
	limit = clampLimit(limit, defaultSyncTailLimit, maxSyncTailLimit)

	tailAfterGlobal := -1
	hasTailAfterGlobal := false
	if q := r.URL.Query().Get("after_global"); q != "" {
		parsed, err := parseNonNegativeInt(q)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid after_global"))
			return
		}
		tailAfterGlobal = parsed
		hasTailAfterGlobal = true
	} else if req.AfterGlobal != nil {
		if *req.AfterGlobal < 0 {
			n.writeRequestError(w, fmt.Errorf("after_global must be non-negative"))
			return
		}
		tailAfterGlobal = *req.AfterGlobal
		hasTailAfterGlobal = true
	}

	filterAfterIndex := -1
	hasFilterAfterIndex := false
	if q := r.URL.Query().Get("after_global_index"); q != "" {
		parsed, err := parseNonNegativeInt(q)
		if err != nil {
			n.writeRequestError(w, fmt.Errorf("invalid after_global_index"))
			return
		}
		filterAfterIndex = parsed
		hasFilterAfterIndex = true
	} else if req.AfterGlobalIndex != nil {
		if *req.AfterGlobalIndex < 0 {
			n.writeRequestError(w, fmt.Errorf("after_global_index must be non-negative"))
			return
		}
		filterAfterIndex = *req.AfterGlobalIndex
		hasFilterAfterIndex = true
	}

	if addrs := r.URL.Query()["addresses"]; len(addrs) > 0 {
		req.Addresses = addrs
	}
	if len(req.Addresses) > maxSyncTailFilterAddresses {
		n.writeRequestError(w, fmt.Errorf("too many addresses: max %d", maxSyncTailFilterAddresses))
		return
	}

	ordered := n.dag.OrderedTransactions()
	dagSize := len(ordered)
	meta := map[string]any{"dag_size": dagSize}

	addrSet := map[string]bool{}
	for _, a := range req.Addresses {
		a = strings.TrimSpace(a)
		if a != "" {
			addrSet[a] = true
		}
	}

	var txs []chain.Transaction
	var hasMore bool
	var next map[string]any

	if len(addrSet) == 0 {
		upper := dagSize
		if hasTailAfterGlobal {
			upper = tailAfterGlobal
		}
		if upper < 0 {
			upper = 0
		}
		start := upper - limit
		if start < 0 {
			start = 0
		}
		txs = append([]chain.Transaction(nil), ordered[start:upper]...)
		hasMore = start > 0
		if hasMore {
			next = map[string]any{"after_global": start - 1}
		}
	} else {
		scanFrom := dagSize - 1
		if hasFilterAfterIndex {
			scanFrom = filterAfterIndex - 1
		}
		collected := []chain.Transaction{}
		lowestIndex := -1
		for i := scanFrom; i >= 0 && len(collected) < limit; i-- {
			tx := ordered[i]
			if txTouchesAddresses(tx, addrSet, n.dag) {
				collected = append(collected, tx)
				lowestIndex = i
			}
		}
		for ii, jj := 0, len(collected)-1; ii < jj; ii, jj = ii+1, jj-1 {
			collected[ii], collected[jj] = collected[jj], collected[ii]
		}
		txs = collected
		hasMore = lowestIndex > 0
		if hasMore {
			next = map[string]any{"after_global_index": lowestIndex - 1}
		}
	}

	if txs == nil {
		txs = []chain.Transaction{}
	}
	n.writeListResponse(w, txs, limit, hasMore, next, meta)
}

func txTouchesAddresses(tx chain.Transaction, addrSet map[string]bool, dag *chain.DAG) bool {
	for _, out := range tx.Outputs {
		if addrSet[out.Address] {
			return true
		}
	}
	for _, in := range tx.Inputs {
		prev := dag.GetTransaction(in.TxID)
		if prev != nil && in.Index >= 0 && in.Index < len(prev.Outputs) {
			if addrSet[prev.Outputs[in.Index].Address] {
				return true
			}
		}
	}
	return false
}

// markAncestorClosure walks backwards from startID through parents and marks
// the entire ancestor closure (including startID) in the provided map.
// It operates on a snapshot of ordered + idxOf so it is safe and fast.
func markAncestorClosure(startID string, marked map[string]bool, idxOf map[string]int, ordered []chain.Transaction) {
	stack := []string{startID}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if marked[id] {
			continue
		}
		marked[id] = true
		if pos, ok := idxOf[id]; ok {
			for _, p := range ordered[pos].Parents {
				if !marked[p] {
					stack = append(stack, p)
				}
			}
		}
	}
}

// handleSync serves POST /v1/sync.
//
// This is the single endpoint for full DAG reconciliation (sync_v1).
//
// Protocol:
//
//	Request:  { "have": ["txid", ...], "limit": 200, "cursor": N }
//	          `have` is a list of tx IDs the caller knows it has. These act as
//	          knowledge anchors. The server uses them to determine exactly what
//	          the caller is missing relative to the server's current frontier.
//
//	Response: {
//	            "common_base": "<txid>",   // first recognized have anchor (diagnostic)
//	            "items":       [...],      // the txs this caller needs (in canonical order)
//	            "want":        ["txid", ...], // txs from `have` that this server would like
//	            "has_more":    bool,
//	            "cursor":      N
//	          }
//
// The server computes the exact set the caller needs as:
//
//	ancestor closure of server's current tips   minus
//	ancestor closures of all the caller's anchors (the `have` list).
//
// This guarantees that a complete sync exchange brings the caller to the
// same frontier as the server (all txs that are ancestors of any of the
// server's current tips).
func (n *Node) handleSync(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req syncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		n.writeRequestError(w, fmt.Errorf("invalid body: %w", err))
		return
	}
	if len(req.Have) > maxSyncHaveLen {
		n.writeRequestError(w, fmt.Errorf("have list too long: max %d", maxSyncHaveLen))
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > syncBatchLimit {
		limit = syncBatchLimit
	}

	ordered := n.dag.OrderedTransactions()

	// Build an index: txID → position in ordered list.
	idxOf := make(map[string]int, len(ordered))
	for i, tx := range ordered {
		idxOf[tx.ID] = i
	}

	// First recognized have anchor (diagnostic; have is most-recent first).
	commonBaseID := ""
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; ok {
			commonBaseID = haveID
			break
		}
	}

	// Bidirectional hint: things in the caller's have list that we don't have.
	var want []string
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; !ok {
			want = append(want, haveID)
		}
	}
	if want == nil {
		want = []string{}
	}

	// === Core of sync_v1: compute exactly what this caller is missing ===
	//
	// 1. Mark everything the caller has told us it has (full ancestor closures
	//    of every anchor in `have` that we recognize).
	clientKnown := make(map[string]bool, len(ordered))
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; ok {
			markAncestorClosure(haveID, clientKnown, idxOf, ordered)
		}
	}

	// 2. Start from our current tips and collect the full ancestor set we want
	//    the caller to have.
	serverTips := n.dag.Tips()
	needed := make(map[string]bool)
	for _, tip := range serverTips {
		markAncestorClosure(tip, needed, idxOf, ordered)
	}

	// 3. Subtract what the caller already knows.
	for id := range clientKnown {
		delete(needed, id)
	}

	// 4. Build the list of missing txs in the canonical (parent-before-child) order.
	var missing []chain.Transaction
	for _, tx := range ordered {
		if needed[tx.ID] {
			missing = append(missing, tx)
		}
	}

	// Pagination over the per-client "missing" list using cursor as a simple index.
	start := 0
	if req.Cursor > 0 {
		start = req.Cursor
	}
	if start > len(missing) {
		start = len(missing)
	}

	end := start + limit
	if end > len(missing) {
		end = len(missing)
	}

	items := append([]chain.Transaction(nil), missing[start:end]...)
	hasMore := end < len(missing)
	nextCursor := 0
	if hasMore {
		nextCursor = end
	}
	if items == nil {
		items = []chain.Transaction{}
	}

	n.writeJSON(w, http.StatusOK, syncResponse{
		CommonBase: commonBaseID,
		Items:      items,
		Want:       want,
		HasMore:    hasMore,
		Cursor:     nextCursor,
		Meta: syncMeta{
			DAGSize: len(ordered),
			Order:   syncOrderVersion,
		},
	})
}

func (n *Node) localSyncDAGSummary() syncDAGSummaryResponse {
	tips := n.localSyncDAGTips()
	return syncDAGSummaryResponse{
		DAGSize:         n.dag.Size(),
		TipCount:        len(tips),
		MaxDAGDepth:     n.dag.MaxDepth(),
		TipsFingerprint: tipsFingerprint(tips),
	}
}

func (n *Node) localSyncDAGTips() []string {
	tips := n.dag.Tips()
	if tips == nil {
		return []string{}
	}
	sort.Strings(tips)
	return tips
}

func tipsFingerprint(tips []string) string {
	hasher := sha3.New256()
	for _, tip := range tips {
		_, _ = hasher.Write([]byte(tip))
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
