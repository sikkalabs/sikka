package node

import (
	"time"

	"besoeasy/sikka/internal/chain"
)

const (
	defaultSyncBatchLimit = 200
	syncOrderVersion      = "dag_depth_timestamp_txid_v1"
	discoveryLoopInterval = 15 * time.Minute
	syncActivePeerLimit   = 32
	// peerResponseHeaderTimeout is the max time to wait for the first response
	// header byte from a peer over Tor. Onion-to-onion RTT can exceed 20s on
	// congested circuits, so this must be well above that.
	peerResponseHeaderTimeout = 60 * time.Second
	// outboundRequestTimeout is the end-to-end timeout for a single outbound
	// HTTP request. Set to 100s to survive slow Tor circuits (~28s RTT observed).
	outboundRequestTimeout = 100 * time.Second
	nodeInitialScore       = 10
	syncScoreRewardMax     = 10
	relayFanout            = 16
	relayMaxHops           = 3
	nodeBookFileName       = "nodebook.json"
	nodePruneInterval      = 1 * time.Minute
	nodeFailureBackoffBase = 15 * time.Second
	nodeFailureBackoffMax  = 15 * time.Minute
	nodeStaleAfter         = 24 * time.Hour

	// maxResponseBodyBytes caps JSON responses from remote peers to prevent
	// memory exhaustion attacks. ML-DSA-87 transactions are ~15 KB each in
	// JSON (5184-char pubkey + 9254-char sig hex), so 200 tx/page ≈ 3 MiB.
	// 8 MiB gives headroom for multisig transactions (multiple keys/sigs)
	// without risking mid-page truncation that triggers the stuck-sync guard.
	maxResponseBodyBytes = 8 << 20 // 8 MiB

	// maxAnnouncedAddresses is the maximum number of addresses accepted in a
	// single /v1/discovery/announce request.  Each address is probed via Tor,
	// so an unbounded list would let one request pin a handler for hours.
	maxAnnouncedAddresses = 8

	// maxKnownNodes is the maximum number of peers stored in memory.  Without
	// a cap, gradual announce-spam grows knownNodes without bound.
	maxKnownNodes = 10_000

	maxBulkTxLookupIDs         = 1024
	maxSyncTailFilterAddresses = 64
)

const (
	relayHeaderOrigin = "X-Sikka-Origin-Node"
	relayHeaderSender = "X-Sikka-Relay-From"
	relayHeaderHop    = "X-Sikka-Relay-Hop"

	capabilitySyncV1 = "sync_v1"
)

var syncBatchLimit = defaultSyncBatchLimit

const (
	// maxSyncHaveLen is the maximum number of tx IDs a client may send in
	// the `have` list of a POST /v1/sync request.  32 IDs with exponential
	// spacing cover a DAG of 2^29 (> 500 million) transactions.
	maxSyncHaveLen = 64

	// syncLinearPrefix is the number of linear steps taken at the tip before
	// switching to exponential doubling when building the have list.
	syncLinearPrefix = 3

	// maxSyncCatchUpPages caps pagination loops to avoid unbounded spinning
	// if a peer keeps returning the same non-importable batch.
	maxSyncCatchUpPages = 10000
)

// syncRequest is the body sent by the client to POST /v1/sync.
type syncRequest struct {
	// Have is a list of the caller's own tx IDs, most-recent first,
	// sampled with exponential back-spacing.
	Have  []string `json:"have"`
	Limit int      `json:"limit,omitempty"`
	// Cursor is an offset into the server-computed missing set for this
	// request. The reference client rebuilds `have` each page and always
	// sends 0; third-party clients may paginate with a fixed `have` and
	// pass the previous response's `cursor` when `has_more` is true.
	Cursor int `json:"cursor,omitempty"`
}

// syncMeta is the metadata block in a syncResponse.
type syncMeta struct {
	DAGSize int    `json:"dag_size"`
	Order   string `json:"order,omitempty"`
}

// syncResponse is the envelope returned by POST /v1/sync.
type syncResponse struct {
	// CommonBase is the first recognized `have` ID (most-recent anchor the
	// server shares with the caller). Diagnostic only; empty if none match.
	CommonBase string `json:"common_base"`
	// Items are the transactions the caller is missing, in DAG order.
	Items []chain.Transaction `json:"items"`
	// Want is a list of tx IDs from `have` that this server does not
	// have — a hint for the caller to push those txs back to us.
	Want    []string `json:"want"`
	HasMore bool     `json:"has_more"`
	// Cursor is the opaque offset to use in the next request when HasMore
	// is true.
	Cursor int      `json:"cursor,omitempty"`
	Meta   syncMeta `json:"meta"`
}

type syncStatusResponse struct {
	SoftwareVersion string   `json:"software_version,omitempty"`
	Addresses       []string `json:"addresses,omitempty"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities,omitempty"`
	ConfiguredNodes []string `json:"configured_nodes,omitempty"`
	KnownNodeCount  int      `json:"known_node_count,omitempty"`
	DAGSize         int      `json:"dag_size"`
	TipCount        int      `json:"tip_count,omitempty"`
	MaxDAGDepth     int64    `json:"max_dag_depth,omitempty"`
	TipsFingerprint string   `json:"tips_fingerprint,omitempty"`
	GenesisTxID     string   `json:"genesis_tx_id"`
	Order           string   `json:"order,omitempty"`
}

type syncDAGSummaryResponse struct {
	DAGSize         int    `json:"dag_size"`
	TipCount        int    `json:"tip_count"`
	MaxDAGDepth     int64  `json:"max_dag_depth"`
	TipsFingerprint string `json:"tips_fingerprint"`
}

type syncTailRequest struct {
	Limit            int      `json:"limit,omitempty"`
	AfterGlobal      *int     `json:"after_global,omitempty"`
	AfterGlobalIndex *int     `json:"after_global_index,omitempty"`
	Addresses        []string `json:"addresses,omitempty"`
}

// txsLookupResponse is the envelope returned by POST /v1/txs (bulk ID lookup).
// We only care about the items (full transactions); page/meta are ignored.
type txsLookupResponse struct {
	Items []chain.Transaction `json:"items"`
}

type discoveryAnnounceRequest struct {
	Addresses []string `json:"addresses"`
}

type addressRecord struct {
	url          string
	lastSeen     time.Time
	lastFailed   time.Time
	failureCount int
	nextRetryAt  time.Time
}

type nodeRecord struct {
	bootstrap bool
	score     int
	lastSeen  time.Time
	lastSync  time.Time
	addresses map[string]*addressRecord
	// lastMatchedSize is the remote DAG size we last successfully reconciled
	// with (either no-op match or full catch-up). Used as a high-quality
	// known_size hint for future syncs with this specific peer.
	lastMatchedSize int
}

type syncAttemptResult struct {
	importedTxCount int
}

type persistedNodeBook struct {
	Nodes []persistedNode `json:"nodes"`
}

type persistedNode struct {
	Addresses       []string  `json:"addresses"`
	LastSeen        time.Time `json:"last_seen,omitempty"`
	LastMatchedSize int       `json:"last_matched_size,omitempty"`
}

type relayContext struct {
	origin string
	sender string
	hop    int
}
