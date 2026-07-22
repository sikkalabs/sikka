package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"besoeasy/sikka"
	"besoeasy/sikka/internal/chain"
	"besoeasy/sikka/internal/config"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// testModernAddress is a valid sk1 address used by tests that do not need to
// spend coins. Generated once per test binary run.
var testModernAddress = func() string {
	scheme := mldsa87.Scheme()
	pub, _, err := scheme.GenerateKey()
	if err != nil {
		panic("testModernAddress: " + err.Error())
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		panic("testModernAddress MarshalBinary: " + err.Error())
	}
	addr, err := chain.PolicyAddress(1, []string{hex.EncodeToString(pubBytes)})
	if err != nil {
		panic("testModernAddress PolicyAddress: " + err.Error())
	}
	return addr
}()

func TestStatusHandler(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{
		NodeAddress:         chain.DefaultGenesisAddress(),
		APIPort:             64552,
		DataDir:             t.TempDir(),
		SyncIntervalSeconds: 15,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if got := payload["api_listen"]; got != "0.0.0.0:64552" {
		t.Fatalf("api_listen = %v, want %q", got, "0.0.0.0:64552")
	}
	if got := payload["dag_size"]; got != float64(1) {
		t.Fatalf("dag_size = %v, want 1 (genesis tx)", got)
	}
	if got := payload["tip_count"]; got != float64(1) {
		t.Fatalf("tip_count = %v, want 1", got)
	}
	if got := payload["max_dag_depth"]; got != float64(0) {
		t.Fatalf("max_dag_depth = %v, want 0", got)
	}
	tips, ok := payload["tips"].([]any)
	if !ok {
		t.Fatalf("tips field is not an array: %v", payload["tips"])
	}
	if len(tips) != 1 || tips[0] != n.dag.GenesisID() {
		t.Fatalf("tips = %v, want [%q]", tips, n.dag.GenesisID())
	}
	if got := payload["total_supply"]; got != float64(chain.TotalSupply) {
		t.Fatalf("total_supply = %v, want %d", got, chain.TotalSupply)
	}
	if got := payload["sync_interval_s"]; got != float64(15) {
		t.Fatalf("sync_interval_s = %v, want %d", got, 15)
	}
	if got := payload["node_address"]; got != chain.DefaultGenesisAddress() {
		t.Fatalf("node_address = %v, want %q", got, chain.DefaultGenesisAddress())
	}
	if got := payload["node_message"]; got != "SIKKA "+sikka.CurrentRelease().SoftwareVersion {
		t.Fatalf("node_message = %v, want %q", got, "SIKKA "+sikka.CurrentRelease().SoftwareVersion)
	}
	if got := payload["known_node_count"]; got != float64(0) {
		t.Fatalf("known_node_count = %v, want 0", got)
	}
	if got := payload["submit_pow_base_bits"]; got != float64(chain.BaseTxWorkBits) {
		t.Fatalf("submit_pow_base_bits = %v, want %d", got, chain.BaseTxWorkBits)
	}
	if got := payload["submit_pow_window_seconds"]; got != float64(chain.PowCongestionWindowSeconds) {
		t.Fatalf("submit_pow_window_seconds = %v, want %d", got, chain.PowCongestionWindowSeconds)
	}
	if got := payload["submit_pow_target_tps"]; got != float64(chain.PowTargetTransactionsPerSecond) {
		t.Fatalf("submit_pow_target_tps = %v, want %d", got, chain.PowTargetTransactionsPerSecond)
	}
	if got := payload["submit_pow_bucket_tx"]; got != float64(chain.PowCongestionBucketTransactions) {
		t.Fatalf("submit_pow_bucket_tx = %v, want %d", got, chain.PowCongestionBucketTransactions)
	}
	if got := payload["submit_pow_bucket_bits"]; got != float64(chain.PowCongestionBucketBits) {
		t.Fatalf("submit_pow_bucket_bits = %v, want %d", got, chain.PowCongestionBucketBits)
	}
	if got := payload["submit_pow_bucket_work_factor"]; got != float64(1<<chain.PowCongestionBucketBits) {
		t.Fatalf("submit_pow_bucket_work_factor = %v, want %d", got, 1<<chain.PowCongestionBucketBits)
	}
	if got := payload["max_future_skew_seconds"]; got != float64(chain.MaxFutureSkewSeconds) {
		t.Fatalf("max_future_skew_seconds = %v, want %d", got, chain.MaxFutureSkewSeconds)
	}
	if got := payload["mode"]; got != "managed" {
		t.Fatalf("mode = %v, want %q", got, "managed")
	}
	if got := payload["enabled"]; got != true {
		t.Fatalf("enabled = %v, want true", got)
	}
	if got := payload["control_connected"]; got != false {
		t.Fatalf("control_connected = %v, want false", got)
	}
	if got := payload["network_health"]; got != "unavailable" {
		t.Fatalf("network_health = %v, want %q", got, "unavailable")
	}
	if got := payload["bootstrap_progress"]; got != float64(0) {
		t.Fatalf("bootstrap_progress = %v, want 0", got)
	}
	if _, ok := payload["node_id"]; ok {
		t.Fatalf("status payload unexpectedly exposes node_id: %v", payload)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

func TestTxPowQuoteHandler(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})
	req := httptest.NewRequest(http.MethodPost, "/v1/tx/pow-quote", strings.NewReader(`{"parents":["`+n.dag.GenesisID()+`","`+n.dag.GenesisID()+`"],"timestamp":`+fmt.Sprint(time.Now().Unix())+`}`))
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var payload chain.TxPowQuote
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.RequiredBits != chain.BaseTxWorkBits {
		t.Fatalf("RequiredBits = %d, want %d", payload.RequiredBits, chain.BaseTxWorkBits)
	}
	if payload.RecentCount != 0 {
		t.Fatalf("RecentCount = %d, want 0", payload.RecentCount)
	}
	if payload.CongestionBuckets != 0 {
		t.Fatalf("CongestionBuckets = %d, want 0", payload.CongestionBuckets)
	}
	if len(payload.ParentPowHashes) != 2 {
		t.Fatalf("ParentPowHashes len = %d, want 2", len(payload.ParentPowHashes))
	}
	for i, h := range payload.ParentPowHashes {
		if len(h) != 64 {
			t.Fatalf("ParentPowHashes[%d] len = %d, want 64 hex chars", i, len(h))
		}
	}
}

func TestTxSubmitRejectsUnderMinedCongestionTx(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)
	dag := newCongestedTestDAG(t, sender)
	n := newTestNodeWithDAG(config.Config{APIPort: 18120, SyncIntervalSeconds: 1}, dag)

	tx, requiredBits := newUnderMinedCongestionTx(t, dag, sender, receiver)
	if requiredBits <= chain.BaseTxWorkBits {
		t.Fatalf("requiredBits = %d, want greater than base %d", requiredBits, chain.BaseTxWorkBits)
	}

	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tx/submit", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	var payload apiErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v body=%s", err, rec.Body.String())
	}
	if payload.Code != "insufficient_pow" {
		t.Fatalf("code = %q, want insufficient_pow", payload.Code)
	}
	if !strings.Contains(payload.Message, "insufficient PoW") {
		t.Fatalf("message = %q, want insufficient PoW error", payload.Message)
	}
}

func TestSyncFromNodeRejectsUnderMinedCongestionTx(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)
	localDAG := newCongestedTestDAG(t, sender)
	localNode := newTestNodeWithDAG(config.Config{APIPort: 18121, SyncIntervalSeconds: 1}, localDAG)

	invalidTx, requiredBits := newUnderMinedCongestionTx(t, localDAG, sender, receiver)
	if requiredBits <= chain.BaseTxWorkBits {
		t.Fatalf("requiredBits = %d, want greater than base %d", requiredBits, chain.BaseTxWorkBits)
	}
	beforeSize := localDAG.Size()

	release := sikka.CurrentRelease()
	ordered := localDAG.OrderedTransactions()
	chunkTransactions := append(append([]chain.Transaction(nil), ordered...), *invalidTx)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sync/status":
			// Report a larger DAG so the status fast-path does not short-circuit;
			// we want the subsequent chunk fetch + import attempt (which should
			// reject the under-mined tx).
			_ = json.NewEncoder(w).Encode(syncStatusResponse{
				Addresses:       []string{server.URL},
				SoftwareVersion: release.SoftwareVersion,
				ProtocolVersion: release.ProtocolVersion,
				Capabilities:    release.Capabilities,
				GenesisTxID:     localDAG.GenesisID(),
				DAGSize:         len(chunkTransactions),
				TipsFingerprint: "diff-for-test",
			})
		case "/v1/sync":
			writeSyncResponse(w, r, chunkTransactions)
		case "/v1/discovery/nodes":
			_ = json.NewEncoder(w).Encode(discoveryListResponse{Items: []string{}})
		case "/v1/discovery/announce":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"accepted","known_node_count":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := localNode.syncFromNode(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected syncFromNode() error for under-mined congestion tx")
	}
	if !strings.Contains(err.Error(), "insufficient PoW") {
		t.Fatalf("syncFromNode() error = %v, want insufficient PoW", err)
	}
	if localDAG.Size() != beforeSize {
		t.Fatalf("local DAG size = %d, want unchanged %d after rejecting invalid sync tx", localDAG.Size(), beforeSize)
	}
}

func TestNewOutboundHTTPClientUsesTorSocks(t *testing.T) {
	t.Parallel()

	client, err := newOutboundHTTPClient(config.Config{})
	if err != nil {
		t.Fatalf("newOutboundHTTPClient() error = %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected HTTP proxy function to be disabled for SOCKS5 transport")
	}
	if transport.Dial == nil {
		t.Fatal("expected SOCKS5 dialer to be configured")
	}
}

func TestManagedTorArgs(t *testing.T) {
	t.Parallel()

	args := managedTorArgs(config.Config{APIPort: 64552, DataDir: "/tmp/sikka"})
	want := []string{
		"--SocksPort", "127.0.0.1:19050",
		"--ControlPort", "127.0.0.1:19051",
		"--CookieAuthentication", "0",
		"--DataDirectory", "/tmp/sikka/tor",
		"--Log", "notice file /tmp/sikka/tor/tor.log",
		"--Log", "err stderr",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("managedTorArgs() = %v, want %v", args, want)
	}
}

func TestManagedTorPublicURL(t *testing.T) {
	t.Parallel()

	seed, err := config.NodePrivateKeySeed("my-deterministic-node-key")
	if err != nil {
		t.Fatalf("NodePrivateKeySeed() error = %v", err)
	}
	identity, err := onionServiceIdentityFromSeed(seed)
	if err != nil {
		t.Fatalf("onionServiceIdentityFromSeed() error = %v", err)
	}
	if !strings.HasPrefix(identity.URL, "http://") || !strings.HasSuffix(identity.URL, ".onion") {
		t.Fatalf("identity.URL = %q, want onion URL", identity.URL)
	}
	if !strings.HasSuffix(identity.Hostname, ".onion") {
		t.Fatalf("identity.Hostname = %q, want onion hostname", identity.Hostname)
	}
	if !strings.Contains(identity.URL, identity.Hostname) {
		t.Fatalf("identity = %+v, want deterministic hostname in public URL", identity)
	}
}

func TestStatusHandlerUsesConfiguredNodeDisplayFields(t *testing.T) {
	t.Parallel()

	donationAddress := "sikka1p4ktc4mcwzekfauhw2eeqfx5edeffaqtmcv3qaautjkrh55slgrmswvkjvf"
	n := mustNewNode(t, config.Config{
		APIPort:             64552,
		DataDir:             t.TempDir(),
		SyncIntervalSeconds: 15,
		NodeAddress:         donationAddress,
		NodeMessage:         "SIKKA relay v0.0.31",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := payload["node_address"]; got != donationAddress {
		t.Fatalf("node_address = %v, want %q", got, donationAddress)
	}
	if got := payload["node_message"]; got != "SIKKA relay v0.0.31" {
		t.Fatalf("node_message = %v, want %q", got, "SIKKA relay v0.0.31")
	}
}

func TestStatusHandlerIncludesTorFields(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	cfg.APIPort = 64552
	cfg.DataDir = t.TempDir()
	n := mustNewNode(t, cfg)
	n.onionPublicURL = "http://exampleexampleexampleexampleexampleexampleexampleexample.onion"

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := payload["mode"]; got != "managed" {
		t.Fatalf("mode = %v, want %q", got, "managed")
	}
	if got := payload["onion_hostname"]; got != "exampleexampleexampleexampleexampleexampleexampleexample.onion" {
		t.Fatalf("onion_hostname = %v, want onion hostname", got)
	}
	if got := payload["enabled"]; got != true {
		t.Fatalf("enabled = %v, want true", got)
	}
	if got := payload["control_connected"]; got != false {
		t.Fatalf("control_connected = %v, want false", got)
	}
	if got := payload["network_health"]; got != "unavailable" {
		t.Fatalf("network_health = %v, want %q", got, "unavailable")
	}
	if got := payload["bootstrap_progress"]; got != float64(0) {
		t.Fatalf("bootstrap_progress = %v, want 0", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

func TestParseTorNetworkHealthConnected(t *testing.T) {
	t.Parallel()

	health := parseTorNetworkHealth(
		[]string{`status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"`},
		[]string{"status/circuit-established=1"},
	)

	if health.NetworkHealth != "connected" {
		t.Fatalf("NetworkHealth = %q, want %q", health.NetworkHealth, "connected")
	}
	if health.BootstrapProgress != 100 {
		t.Fatalf("BootstrapProgress = %d, want 100", health.BootstrapProgress)
	}
	if health.BootstrapTag != "done" {
		t.Fatalf("BootstrapTag = %q, want %q", health.BootstrapTag, "done")
	}
	if health.BootstrapSummary != "Done" {
		t.Fatalf("BootstrapSummary = %q, want %q", health.BootstrapSummary, "Done")
	}
	if !health.CircuitEstablished {
		t.Fatal("CircuitEstablished = false, want true")
	}
}

func TestParseTorNetworkHealthBootstrapping(t *testing.T) {
	t.Parallel()

	health := parseTorNetworkHealth(
		[]string{`status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=45 TAG=conn_or SUMMARY="Connecting to a relay" WARNING="Connection timed out" REASON=TIMEOUT`},
		[]string{"status/circuit-established=0"},
	)

	if health.NetworkHealth != "bootstrapping" {
		t.Fatalf("NetworkHealth = %q, want %q", health.NetworkHealth, "bootstrapping")
	}
	if health.BootstrapProgress != 45 {
		t.Fatalf("BootstrapProgress = %d, want 45", health.BootstrapProgress)
	}
	if health.BootstrapTag != "conn_or" {
		t.Fatalf("BootstrapTag = %q, want %q", health.BootstrapTag, "conn_or")
	}
	if health.BootstrapSummary != "Connecting to a relay" {
		t.Fatalf("BootstrapSummary = %q, want %q", health.BootstrapSummary, "Connecting to a relay")
	}
	if health.BootstrapWarning != "Connection timed out" {
		t.Fatalf("BootstrapWarning = %q, want %q", health.BootstrapWarning, "Connection timed out")
	}
	if health.CircuitEstablished {
		t.Fatal("CircuitEstablished = true, want false")
	}
}

func TestParseTorNetworkHealthUsesLatestReply(t *testing.T) {
	t.Parallel()

	health := parseTorNetworkHealth(
		[]string{
			`status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=10 TAG=conn SUMMARY="Starting"`,
			`status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"`,
		},
		[]string{"status/circuit-established=0", "status/circuit-established=1"},
	)

	if health.BootstrapProgress != 100 {
		t.Fatalf("BootstrapProgress = %d, want 100", health.BootstrapProgress)
	}
	if health.BootstrapTag != "done" {
		t.Fatalf("BootstrapTag = %q, want %q", health.BootstrapTag, "done")
	}
	if !health.CircuitEstablished {
		t.Fatal("CircuitEstablished = false, want true")
	}
}

func TestStaticTxPageRoute(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	req := httptest.NewRequest(http.MethodGet, "/tx/1a6d7db121e2547e37df8b525543cd5ef8e8d3a278959383892a1684d9f2ac68", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if body := rec.Body.String(); !strings.Contains(body, "Transaction") {
		t.Fatal("expected tx page html response body")
	}
}

func TestStaticWalletAddressPageRoute(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	req := httptest.NewRequest(http.MethodGet, "/wallet/sikka1pfspfrt5052sj47x6t4a5a9laq7auzamwq4dc9ccpdlq5g5y0wn7qn5tdm4", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); !strings.Contains(body, "Address") {
		t.Fatal("expected wallet address page html response body")
	}
}

func TestRootRouteServesIndex(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if body := rec.Body.String(); !strings.Contains(body, "<title>Sikka Node</title>") {
		t.Fatal("expected root route to serve the current node homepage")
	}
}

func TestStaticWalletRoutesRemoved(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	for _, path := range []string{"/wallet.html", "/paperwallet.html", "/multisig-wallet.html"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		n.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("path %s status code = %d, want %d (standalone wallet HTML was removed)", path, rec.Code, http.StatusNotFound)
		}
	}
}

func TestStandaloneDAGSummaryRoutesRemoved(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	for _, path := range []string{"/v1/chain/info", "/v1/dag/tips", "/v1/dag/depth"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		n.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status code = %d, want %d", path, rec.Code, http.StatusNotFound)
		}
	}
}

func TestTxWeightHandler(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})
	genesisID := n.dag.GenesisID()

	req := httptest.NewRequest(http.MethodGet, "/v1/tx/"+genesisID+"/weight", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := payload["txid"].(string); got != genesisID {
		t.Fatalf("txid = %q, want %q", got, genesisID)
	}
	if weight, ok := payload["weight"].(float64); !ok || weight < 1 {
		t.Fatalf("weight = %v, want >= 1", payload["weight"])
	}
}

func TestTxWeightHandlerNotFound(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir()})

	req := httptest.NewRequest(http.MethodGet, "/v1/tx/nonexistenttxid/weight", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAddressHandler(t *testing.T) {
	t.Parallel()

	dag := newTestDAGWithGenesis(t, testModernAddress)
	n := newTestNodeWithDAG(config.Config{APIPort: 64552, SyncIntervalSeconds: 15}, dag)

	req := httptest.NewRequest(http.MethodGet, "/v1/address/"+testModernAddress, nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	meta, ok := payload["meta"].(map[string]any)
	if !ok {
		t.Fatalf("meta field missing: %v", payload["meta"])
	}
	if got := meta["address"]; got != testModernAddress {
		t.Fatalf("address = %v, want %q", got, testModernAddress)
	}
	if got := meta["utxo_count"]; got != float64(1) {
		t.Fatalf("utxo_count = %v, want 1", meta["utxo_count"])
	}
	items, ok := payload["items"].([]any)
	if !ok {
		t.Fatalf("items field is not an array: %v", payload["items"])
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if got := meta["balance"].(float64); got <= 0 {
		t.Fatalf("balance = %v, want > 0", meta["balance"])
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

func TestSyncStatusHandler(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{
		APIPort:             64552,
		DataDir:             t.TempDir(),
		SyncIntervalSeconds: 15,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/sync/status", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	release := sikka.CurrentRelease()
	if got := payload["software_version"]; got != release.SoftwareVersion {
		t.Fatalf("software_version = %v, want %q", got, release.SoftwareVersion)
	}
	if got := payload["protocol_version"]; got != release.ProtocolVersion {
		t.Fatalf("protocol_version = %v, want %q", got, release.ProtocolVersion)
	}
	if got := payload["capabilities"]; !reflect.DeepEqual(got, toAnySlice(release.Capabilities)) {
		t.Fatalf("capabilities = %v, want %v", got, release.Capabilities)
	}
	if got := payload["dag_size"]; got != float64(1) {
		t.Fatalf("dag_size = %v, want 1 (genesis tx)", got)
	}
	if got := payload["tip_count"]; got != float64(1) {
		t.Fatalf("tip_count = %v, want 1", got)
	}
	if got := payload["max_dag_depth"]; got != float64(0) {
		t.Fatalf("max_dag_depth = %v, want 0", got)
	}
	if got := payload["tips_fingerprint"]; got == "" {
		t.Fatal("expected non-empty tips_fingerprint")
	}
	if got := payload["genesis_tx_id"]; got != n.dag.GenesisID() {
		t.Fatalf("genesis_tx_id = %v, want %q", got, n.dag.GenesisID())
	}
	if got := payload["order"]; got != syncOrderVersion {
		t.Fatalf("order = %v, want %q", got, syncOrderVersion)
	}
	if _, ok := payload["chunk_size"]; ok {
		t.Fatalf("sync status payload unexpectedly exposes chunk_size: %v", payload)
	}
	if _, ok := payload["node_id"]; ok {
		t.Fatalf("sync status payload unexpectedly exposes node_id: %v", payload)
	}
}

// (Bloom unit tests removed — bloom_sync_v1 deleted. The core sync logic
// now lives in POST /v1/sync.)

func TestSyncTailFilteredPOSTFirstPage(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)
	n := newTestNodeWithDAG(config.Config{APIPort: 64552, SyncIntervalSeconds: 15}, newTestDAGWithGenesis(t, sender.address))

	genesisUTXO := n.dag.GetUTXOs(sender.address)[0]
	tip1, tip2 := n.dag.SelectTips()
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: genesisUTXO.Value}},
		Timestamp: time.Now().Unix(),
	}
	sender.sign(t, tx, 0, genesisUTXO)
	mineWithDAG(t, n.dag, tx, 1)
	if err := n.dag.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}

	body, _ := json.Marshal(syncTailRequest{
		Limit:     10,
		Addresses: []string{receiver.address},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/tail", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var payload listEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	items, ok := payload.Items.([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
}

func TestSyncTailRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir(), SyncIntervalSeconds: 15})
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/tail", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestTxsBulkLookupRejectsTooManyIDs(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir(), SyncIntervalSeconds: 15})
	ids := make([]string, maxBulkTxLookupIDs+1)
	for i := range ids {
		ids[i] = strings.Repeat("a", 64)
	}
	body, _ := json.Marshal(ids)
	req := httptest.NewRequest(http.MethodPost, "/v1/txs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestSyncHandler(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)
	n := newTestNodeWithDAG(config.Config{APIPort: 64552, SyncIntervalSeconds: 15}, newTestDAGWithGenesis(t, sender.address))

	genesisUTXO := n.dag.GetUTXOs(sender.address)[0]
	tip1, tip2 := n.dag.SelectTips()
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: genesisUTXO.Value}},
		Timestamp: time.Now().Unix(),
	}
	sender.sign(t, tx, 0, genesisUTXO)
	mineWithDAG(t, n.dag, tx, 1)
	if err := n.dag.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}

	// Empty have list => client has nothing; server should return genesis + tx.
	bodyEmpty, _ := json.Marshal(syncRequest{Have: []string{}, Limit: 100})
	reqEmpty := httptest.NewRequest(http.MethodPost, "/v1/sync", strings.NewReader(string(bodyEmpty)))
	reqEmpty.Header.Set("Content-Type", "application/json")
	recEmpty := httptest.NewRecorder()
	n.routes().ServeHTTP(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusOK {
		t.Fatalf("empty have status = %d: %s", recEmpty.Code, recEmpty.Body.String())
	}
	var respEmpty syncResponse
	if err := json.Unmarshal(recEmpty.Body.Bytes(), &respEmpty); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(respEmpty.Items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(respEmpty.Items))
	}

	// Have list with genesis only => missing child tx.
	bodyPartial, _ := json.Marshal(syncRequest{Have: []string{n.dag.GenesisID()}, Limit: 100})
	reqPartial := httptest.NewRequest(http.MethodPost, "/v1/sync", strings.NewReader(string(bodyPartial)))
	reqPartial.Header.Set("Content-Type", "application/json")
	recPartial := httptest.NewRecorder()
	n.routes().ServeHTTP(recPartial, reqPartial)
	var respPartial syncResponse
	if err := json.Unmarshal(recPartial.Body.Bytes(), &respPartial); err != nil {
		t.Fatalf("unmarshal partial: %v", err)
	}
	foundChild := false
	for _, item := range respPartial.Items {
		if item.ID == tx.ID {
			foundChild = true
			break
		}
	}
	if !foundChild {
		t.Fatalf("partial response did not contain the expected child tx %s: %v", tx.ID, respPartial.Items)
	}
	if respPartial.HasMore {
		t.Fatal("expected has_more false for single missing tx")
	}
}

func TestDiscoveryNodesEndpointIncludesSelfNode(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18090, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	server := newSyncTestServer(t, n)
	if _, ok, err := n.addKnownNode("https://seed-two.example.com", true, false); err != nil || !ok {
		t.Fatal("expected known node to be added")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/discovery/nodes", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload listEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	peers, ok := payload.Items.([]any)
	if !ok || len(peers) < 2 {
		t.Fatalf("len(items) = %d, want at least 2", len(peers))
	}
	if strings.Contains(rec.Body.String(), "\"node_id\"") {
		t.Fatalf("discovery response unexpectedly exposes node_id: %s", rec.Body.String())
	}
	if peers[0] != server.URL {
		t.Fatalf("items[0] = %v, want %q", peers[0], server.URL)
	}
}

func TestDiscoveryNodesEndpointReturnsBest16Peers(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18099, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	server := newSyncTestServer(t, n)

	for i := 0; i < 20; i++ {
		peerURL := fmt.Sprintf("https://peer-%02d.example.com", i)
		if _, ok, err := n.addKnownNode(peerURL, false, false); err != nil || !ok {
			t.Fatalf("addKnownNode(%q) failed: ok=%v err=%v", peerURL, ok, err)
		}
		normalized, err := normalizeDiscoveredNodeURL(peerURL)
		if err != nil {
			t.Fatalf("normalizeDiscoveredNodeURL(%q) error = %v", peerURL, err)
		}
		n.nodeBookMu.Lock()
		_, record, _ := n.findKnownNodeByAddressLocked(normalized)
		record.score = i
		n.nodeBookMu.Unlock()
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/discovery/nodes?limit=16", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload listEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	peerItems, ok := payload.Items.([]any)
	if !ok || len(peerItems) != 16 {
		t.Fatalf("len(items) = %d, want 16", len(peerItems))
	}
	if peerItems[0] != server.URL {
		t.Fatalf("items[0] = %v, want %q", peerItems[0], server.URL)
	}
	peers := strings.Join(mustStringSlice(peerItems), "\n")
	if !strings.Contains(peers, "https://peer-19.example.com") {
		t.Fatalf("expected top-scored peer in payload: %v", peerItems)
	}
	if strings.Contains(peers, "https://peer-00.example.com") {
		t.Fatalf("did not expect low-scored peer in payload: %v", peerItems)
	}
}

func TestDiscoveryNodesEndpointSkipsCoolingDownPeers(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18100, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	server := newSyncTestServer(t, n)

	hotPeer := "https://hot-peer.example.com"
	coolPeer := "https://cooling-peer.example.com"
	for _, peerURL := range []string{hotPeer, coolPeer} {
		if _, ok, err := n.addKnownNode(peerURL, false, false); err != nil || !ok {
			t.Fatalf("addKnownNode(%q) failed: ok=%v err=%v", peerURL, ok, err)
		}
		normalized, err := normalizeDiscoveredNodeURL(peerURL)
		if err != nil {
			t.Fatalf("normalizeDiscoveredNodeURL(%q) error = %v", peerURL, err)
		}
		n.nodeBookMu.Lock()
		_, record, state := n.findKnownNodeByAddressLocked(normalized)
		record.score = 100
		if peerURL == coolPeer {
			state.nextRetryAt = time.Now().Add(10 * time.Minute)
		}
		n.nodeBookMu.Unlock()
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/discovery/nodes", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload listEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	peerItems, ok := payload.Items.([]any)
	if !ok || len(peerItems) == 0 {
		t.Fatal("expected discovery items")
	}
	if peerItems[0] != server.URL {
		t.Fatalf("items[0] = %v, want %q", peerItems[0], server.URL)
	}
	peers := strings.Join(mustStringSlice(peerItems), "\n")
	if !strings.Contains(peers, hotPeer) {
		t.Fatalf("expected available peer in payload: %v", peerItems)
	}
	if strings.Contains(peers, coolPeer) {
		t.Fatalf("did not expect cooling-down peer in payload: %v", peerItems)
	}
}

func TestDiscoveryAnnounceAddsKnownNode(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18096, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	release := sikka.CurrentRelease()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sync/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(syncStatusResponse{
			Addresses:       []string{server.URL},
			ProtocolVersion: release.ProtocolVersion,
			GenesisTxID:     n.dag.GenesisID(),
		})
	}))
	defer server.Close()
	req := httptest.NewRequest(http.MethodPost, "/v1/discovery/announce", strings.NewReader(`{"addresses":["`+server.URL+`"]}`))
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := n.knownNodeURLs(8); len(got) != 1 || got[0] != server.URL {
		t.Fatalf("knownNodeURLs() = %v, want [%s]", got, server.URL)
	}

	normalized, err := normalizeDiscoveredNodeURL(server.URL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL() error = %v", err)
	}
	n.nodeBookMu.RLock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	n.nodeBookMu.RUnlock()
	if record == nil {
		t.Fatal("expected announced peer to be tracked")
	}
	if len(record.addresses) != 1 {
		t.Fatalf("len(record.addresses) = %d, want 1", len(record.addresses))
	}
	if _, ok := record.addresses[server.URL]; !ok {
		t.Fatalf("expected record.addresses to include %q", server.URL)
	}
}

func TestDiscoveryAnnounceRejectsPeerWithProtocolMismatch(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18098, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sync/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(syncStatusResponse{
			Addresses:       []string{server.URL},
			ProtocolVersion: "999",
			GenesisTxID:     "genesis-mismatch",
		})
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/discovery/announce", strings.NewReader(`{"addresses":["`+server.URL+`"]}`))
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := n.knownNodeURLs(8); len(got) != 0 {
		t.Fatalf("knownNodeURLs() = %v, want none", got)
	}
}

func TestRemovedSyncNodesEndpointReturnsNotFound(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 18097, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	req := httptest.NewRequest(http.MethodGet, "/v1/sync/nodes", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestNodeBookPersistsDiscoveredNodesAcrossRestart(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	n := mustNewNode(t, config.Config{APIPort: 18091, DataDir: dataDir, SyncIntervalSeconds: 1})
	if _, ok, err := n.addKnownNode("https://node-one.example.com", false, true); err != nil || !ok {
		t.Fatal("expected discovered node to be accepted")
	}

	restarted := mustNewNode(t, config.Config{APIPort: 18092, DataDir: dataDir, SyncIntervalSeconds: 1})
	if restarted.knownNodeCount() != 1 {
		t.Fatalf("knownNodeCount() = %d, want 1", restarted.knownNodeCount())
	}
	if got := restarted.knownNodeURLs(8); len(got) != 1 || got[0] != "https://node-one.example.com" {
		t.Fatalf("knownNodeURLs() = %v, want [https://node-one.example.com]", got)
	}
}

func TestPruneKnownNodesEvictsDeadNodeAndUpdatesNodeBook(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	n := mustNewNode(t, config.Config{APIPort: 18093, DataDir: dataDir, SyncIntervalSeconds: 1})
	key, ok, err := n.addKnownPeer([]string{"https://node-two.example.com"}, false, true)
	if err != nil || !ok {
		t.Fatal("expected discovered node to be accepted")
	}
	n.nodeBookMu.Lock()
	record := n.knownNodes[key]
	record.lastSeen = time.Now().Add(-2 * nodeStaleAfter)
	n.nodeBookMu.Unlock()

	if removed := n.pruneKnownNodes(time.Now()); removed != 1 {
		t.Fatalf("pruneKnownNodes() removed %d nodes, want 1", removed)
	}
	restarted := mustNewNode(t, config.Config{APIPort: 18094, DataDir: dataDir, SyncIntervalSeconds: 1})
	if restarted.knownNodeCount() != 0 {
		t.Fatalf("knownNodeCount() after restart = %d, want 0", restarted.knownNodeCount())
	}
}

func TestLoadNodeBookSkipsStaleNode(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	stored := persistedNodeBook{Nodes: []persistedNode{{
		Addresses: []string{"https://stale.example.com"},
		LastSeen:  time.Now().Add(-2 * nodeStaleAfter),
	}, {
		Addresses: []string{"https://fresh.example.com"},
		LastSeen:  time.Now(),
	}}}
	payload, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, nodeBookFileName), payload, 0o644); err != nil {
		t.Fatalf("WriteFile(nodebook.json) error = %v", err)
	}

	n := mustNewNode(t, config.Config{APIPort: 18095, DataDir: dataDir, SyncIntervalSeconds: 1})
	if got := n.knownNodeURLs(8); len(got) != 1 || got[0] != "https://fresh.example.com" {
		t.Fatalf("knownNodeURLs() = %v, want [https://fresh.example.com]", got)
	}
}

func TestLoadNodeBookKeepsOnionAddress(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	onionURL := "http://sfn7igfjj4vwat2m3lnkwrv3iu4jqhnlqzzj4lgz6nsvrjwkxq66jsid.onion"
	stored := persistedNodeBook{Nodes: []persistedNode{{
		Addresses: []string{onionURL},
		LastSeen:  time.Now(),
	}}}
	payload, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, nodeBookFileName), payload, 0o644); err != nil {
		t.Fatalf("WriteFile(nodebook.json) error = %v", err)
	}

	n := mustNewNode(t, config.Config{APIPort: 18101, DataDir: dataDir, SyncIntervalSeconds: 1})
	normalized, err := normalizeDiscoveredNodeURL(onionURL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL() error = %v", err)
	}
	n.nodeBookMu.RLock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	n.nodeBookMu.RUnlock()
	if record == nil {
		t.Fatal("expected persisted onion peer to be loaded")
	}
	if len(record.addresses) != 1 {
		t.Fatalf("len(record.addresses) = %d, want 1", len(record.addresses))
	}
}

func TestHTTPRelayTransactionsAcrossKnownNodes(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)

	dagA := newTestDAGWithGenesis(t, sender.address)
	dagB := newTestDAGWithGenesis(t, sender.address)
	dagC := newTestDAGWithGenesis(t, sender.address)

	nodeA := newTestNodeWithDAG(config.Config{APIPort: 19100, SyncIntervalSeconds: 1}, dagA)
	nodeB := newTestNodeWithDAG(config.Config{APIPort: 19101, SyncIntervalSeconds: 1}, dagB)
	nodeC := newTestNodeWithDAG(config.Config{APIPort: 19102, SyncIntervalSeconds: 1}, dagC)
	serverA := newSyncTestServer(t, nodeA)
	_ = serverA
	serverB := newSyncTestServer(t, nodeB)
	serverC := newSyncTestServer(t, nodeC)

	if _, ok, err := nodeA.addKnownNode(serverB.URL, true, false); err != nil || !ok {
		t.Fatal("expected node A to know node B")
	}
	if _, ok, err := nodeB.addKnownNode(serverC.URL, true, false); err != nil || !ok {
		t.Fatal("expected node B to know node C")
	}

	spendable := dagA.GetUTXOs(sender.address)[0]
	tip1, tip2 := dagA.SelectTips()
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: spendable.TxID, Index: spendable.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: spendable.Value}},
		Timestamp: time.Now().Unix(), // must be set before mining so PoW is stable
	}
	sender.sign(t, tx, 0, spendable)
	mineWithDAG(t, dagA, tx, 1)

	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/tx/submit", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	nodeA.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var submitted struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &submitted); err != nil {
		t.Fatalf("json.Unmarshal(response) error = %v", err)
	}
	if submitted.TxID == "" {
		t.Fatal("expected submit response to include txid")
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return dagB.GetTransaction(submitted.TxID) != nil
	}, "transaction to relay across A -> B")

	waitForCondition(t, 2*time.Second, func() bool {
		return dagC.GetTransaction(submitted.TxID) != nil
	}, "transaction to relay across A -> B -> C")
}

func TestSyncFromNodeCatchesUpMissingTransactions(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)

	localDAG := newTestDAGWithGenesis(t, sender.address)
	remoteDAG := newTestDAGWithGenesis(t, sender.address)

	localNode := newTestNodeWithDAG(config.Config{APIPort: 19110, SyncIntervalSeconds: 1}, localDAG)
	remoteNode := newTestNodeWithDAG(config.Config{APIPort: 19111, SyncIntervalSeconds: 1}, remoteDAG)
	remoteServer := newSyncTestServer(t, remoteNode)

	genesisUTXO := remoteDAG.GetUTXOs(sender.address)[0]
	tip1, tip2 := remoteDAG.SelectTips()
	baseTime := time.Now().Unix() - 2000
	tx1 := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: genesisUTXO.Value}},
		Timestamp: baseTime,
	}
	sender.sign(t, tx1, 0, genesisUTXO)
	mineWithDAG(t, remoteDAG, tx1, 1)
	if err := remoteDAG.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx(tx1) error = %v", err)
	}

	remoteSpendable := remoteDAG.GetUTXOs(receiver.address)[0]
	tip3, tip4 := remoteDAG.SelectTips()
	tx2 := &chain.Transaction{
		Parents:   []string{tip3, tip4},
		Inputs:    []chain.TxInput{{TxID: remoteSpendable.TxID, Index: remoteSpendable.Index}},
		Outputs:   []chain.TxOutput{{Address: sender.address, Value: remoteSpendable.Value}},
		Timestamp: baseTime + chain.MinUTXOMaturitySeconds + 1,
	}
	receiver.sign(t, tx2, 0, remoteSpendable)
	mineWithDAG(t, remoteDAG, tx2, 1)
	if err := remoteDAG.SubmitTx(tx2); err != nil {
		t.Fatalf("SubmitTx(tx2) error = %v", err)
	}

	if localDAG.GetTransaction(tx1.ID) != nil || localDAG.GetTransaction(tx2.ID) != nil {
		t.Fatal("expected local DAG to start without remote transactions")
	}

	if err := localNode.syncFromNode(context.Background(), remoteServer.URL); err != nil {
		t.Fatalf("syncFromNode() error = %v", err)
	}
	if localDAG.GetTransaction(tx1.ID) == nil {
		t.Fatalf("expected local DAG to import tx1 %q", tx1.ID)
	}
	if localDAG.GetTransaction(tx2.ID) == nil {
		t.Fatalf("expected local DAG to import tx2 %q", tx2.ID)
	}
}

func TestSyncCatchUpMultiPage(t *testing.T) {
	t.Parallel()

	oldLimit := syncBatchLimit
	syncBatchLimit = 2
	t.Cleanup(func() { syncBatchLimit = oldLimit })

	sender := newTestWallet(t)
	receiver := newTestWallet(t)

	localDAG := newTestDAGWithGenesis(t, sender.address)
	remoteDAG := newTestDAGWithGenesis(t, sender.address)
	localNode := newTestNodeWithDAG(config.Config{APIPort: 19114, SyncIntervalSeconds: 1}, localDAG)
	remoteNode := newTestNodeWithDAG(config.Config{APIPort: 19115, SyncIntervalSeconds: 1}, remoteDAG)
	remoteServer := newSyncTestServer(t, remoteNode)

	const extraTxCount = 5
	remoteTxIDs := appendLinearTestTxs(t, remoteDAG, sender, receiver, extraTxCount)

	if err := localNode.syncFromNode(context.Background(), remoteServer.URL); err != nil {
		t.Fatalf("syncFromNode() error = %v", err)
	}
	for _, txID := range remoteTxIDs {
		if localDAG.GetTransaction(txID) == nil {
			t.Fatalf("expected local DAG to import tx %q after multi-page sync", txID)
		}
	}
	if localDAG.Size() != remoteDAG.Size() {
		t.Fatalf("local dag_size = %d, want %d", localDAG.Size(), remoteDAG.Size())
	}
}

func TestRunDiscoveryRoundAddsPeersAndRewardsNode(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 19113, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/discovery/nodes" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(discoveryListResponse{Items: []string{"https://peer-a.example.com"}})
	}))
	defer server.Close()

	if _, ok, err := n.addKnownNode(server.URL, true, false); err != nil || !ok {
		t.Fatal("expected discovery peer to be added")
	}
	normalized, err := normalizeDiscoveredNodeURL(server.URL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL() error = %v", err)
	}
	n.nodeBookMu.RLock()
	_, record, _ := n.findKnownNodeByAddressLocked(normalized)
	initialScore := record.score
	n.nodeBookMu.RUnlock()

	if err := n.runDiscoveryRound(context.Background()); err != nil {
		t.Fatalf("runDiscoveryRound() error = %v", err)
	}

	if got := n.knownNodeURLs(8); len(got) != 2 {
		t.Fatalf("knownNodeURLs() len = %d, want 2", len(got))
	}
	n.nodeBookMu.RLock()
	_, record, _ = n.findKnownNodeByAddressLocked(normalized)
	updatedScore := record.score
	n.nodeBookMu.RUnlock()
	if updatedScore != initialScore+1 {
		t.Fatalf("record.score = %d, want %d", updatedScore, initialScore+1)
	}
}

func TestTopSyncCandidateURLsPrefersHigherScores(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 19116, DataDir: t.TempDir(), SyncIntervalSeconds: 1})
	highScoreURL := "https://high-score.example.com"
	midScoreURL := "https://mid-score.example.com"
	lowScoreURL := "https://low-score.example.com"

	if _, ok, err := n.addKnownNode(lowScoreURL, false, false); err != nil || !ok {
		t.Fatalf("addKnownNode(%q) error = %v, ok = %v", lowScoreURL, err, ok)
	}
	if _, ok, err := n.addKnownNode(midScoreURL, false, false); err != nil || !ok {
		t.Fatalf("addKnownNode(%q) error = %v, ok = %v", midScoreURL, err, ok)
	}
	if _, ok, err := n.addKnownNode(highScoreURL, false, false); err != nil || !ok {
		t.Fatalf("addKnownNode(%q) error = %v, ok = %v", highScoreURL, err, ok)
	}

	n.adjustNodeScore(midScoreURL, 5)
	n.adjustNodeScore(highScoreURL, 10)

	candidates := n.topSyncCandidateURLs(3)
	if len(candidates) != 3 {
		t.Fatalf("len(topSyncCandidateURLs()) = %d, want 3", len(candidates))
	}
	if candidates[0] != highScoreURL {
		t.Fatalf("candidates[0] = %q, want %q", candidates[0], highScoreURL)
	}
	if candidates[1] != midScoreURL {
		t.Fatalf("candidates[1] = %q, want %q", candidates[1], midScoreURL)
	}
	if candidates[2] != lowScoreURL {
		t.Fatalf("candidates[2] = %q, want %q", candidates[2], lowScoreURL)
	}
}

func TestRunSyncRoundRewardsSuccessfulNode(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)

	localDAG := newTestDAGWithGenesis(t, sender.address)
	remoteDAG := newTestDAGWithGenesis(t, sender.address)
	localNode := newTestNodeWithDAG(config.Config{APIPort: 19114, SyncIntervalSeconds: 1}, localDAG)
	remoteNode := newTestNodeWithDAG(config.Config{APIPort: 19115, SyncIntervalSeconds: 1}, remoteDAG)
	remoteServer := newSyncTestServer(t, remoteNode)

	genesisUTXO := remoteDAG.GetUTXOs(sender.address)[0]
	tip1, tip2 := remoteDAG.SelectTips()
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: genesisUTXO.Value}},
		Timestamp: time.Now().Unix(),
	}
	sender.sign(t, tx, 0, genesisUTXO)
	mineWithDAG(t, remoteDAG, tx, 1)
	if err := remoteDAG.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}

	if _, ok, err := localNode.addKnownNode(remoteServer.URL, true, false); err != nil || !ok {
		t.Fatal("expected sync peer to be added")
	}
	normalized, err := normalizeDiscoveredNodeURL(remoteServer.URL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL() error = %v", err)
	}
	localNode.nodeBookMu.RLock()
	_, record, _ := localNode.findKnownNodeByAddressLocked(normalized)
	initialScore := record.score
	localNode.nodeBookMu.RUnlock()

	if err := localNode.runSyncRound(context.Background()); err != nil {
		t.Fatalf("runSyncRound() error = %v", err)
	}
	if localDAG.GetTransaction(tx.ID) == nil {
		t.Fatalf("expected local DAG to import synced tx %q", tx.ID)
	}
	localNode.nodeBookMu.RLock()
	_, record, _ = localNode.findKnownNodeByAddressLocked(normalized)
	updatedScore := record.score
	localNode.nodeBookMu.RUnlock()
	if updatedScore <= initialScore {
		t.Fatalf("record.score = %d, want > %d", updatedScore, initialScore)
	}
}

func TestRunSyncRoundSyncsMultiplePeersPerRound(t *testing.T) {
	t.Parallel()

	sender := newTestWallet(t)
	receiver := newTestWallet(t)

	localDAG := newTestDAGWithGenesis(t, sender.address)
	firstRemoteDAG := newTestDAGWithGenesis(t, sender.address)
	secondRemoteDAG := newTestDAGWithGenesis(t, sender.address)

	localNode := newTestNodeWithDAG(config.Config{APIPort: 19117, SyncIntervalSeconds: 1}, localDAG)
	firstRemoteNode := newTestNodeWithDAG(config.Config{APIPort: 19118, SyncIntervalSeconds: 1}, firstRemoteDAG)
	secondRemoteNode := newTestNodeWithDAG(config.Config{APIPort: 19119, SyncIntervalSeconds: 1}, secondRemoteDAG)
	firstRemoteServer := newSyncTestServer(t, firstRemoteNode)
	secondRemoteServer := newSyncTestServer(t, secondRemoteNode)

	genesisUTXO := secondRemoteDAG.GetUTXOs(sender.address)[0]
	tip1, tip2 := secondRemoteDAG.SelectTips()
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: genesisUTXO.Value}},
		Timestamp: time.Now().Unix(),
	}
	sender.sign(t, tx, 0, genesisUTXO)
	mineWithDAG(t, secondRemoteDAG, tx, 1)
	if err := secondRemoteDAG.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}

	if _, ok, err := localNode.addKnownNode(firstRemoteServer.URL, true, false); err != nil || !ok {
		t.Fatal("expected first sync peer to be added")
	}
	if _, ok, err := localNode.addKnownNode(secondRemoteServer.URL, false, false); err != nil || !ok {
		t.Fatal("expected second sync peer to be added")
	}

	if err := localNode.runSyncRound(context.Background()); err != nil {
		t.Fatalf("runSyncRound() error = %v", err)
	}
	if localDAG.GetTransaction(tx.ID) == nil {
		t.Fatalf("expected local DAG to import synced tx %q from the second peer in the same round", tx.ID)
	}

	firstNormalized, err := normalizeDiscoveredNodeURL(firstRemoteServer.URL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL(firstRemoteServer) error = %v", err)
	}
	secondNormalized, err := normalizeDiscoveredNodeURL(secondRemoteServer.URL)
	if err != nil {
		t.Fatalf("normalizeDiscoveredNodeURL(secondRemoteServer) error = %v", err)
	}

	localNode.nodeBookMu.RLock()
	_, firstRecord, _ := localNode.findKnownNodeByAddressLocked(firstNormalized)
	_, secondRecord, _ := localNode.findKnownNodeByAddressLocked(secondNormalized)
	localNode.nodeBookMu.RUnlock()
	if (firstRecord == nil || firstRecord.lastSync.IsZero()) && (secondRecord == nil || secondRecord.lastSync.IsZero()) {
		t.Fatal("expected at least one peer to be synced in this round")
	}
}

// ---- helpers ----

func mustNewNode(t *testing.T, cfg config.Config) *Node {
	t.Helper()
	n, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	n.torHTTPClient = &http.Client{Timeout: 10 * time.Second}
	return n
}

func newTestNodeWithDAG(cfg config.Config, dag *chain.DAG) *Node {
	return &Node{
		log:            initNodeLogger(),
		config:         cfg,
		onionPublicURL: fmt.Sprintf("http://test-node-%d.onion", cfg.APIPort),
		dag:            dag,
		torHTTPClient:  &http.Client{Timeout: 10 * time.Second},
		knownNodes:     make(map[string]*nodeRecord),
	}
}

func newCongestedTestDAG(t *testing.T, wallet testWallet) *chain.DAG {
	t.Helper()

	dataDir := t.TempDir()
	bootstrap, err := chain.NewDAG(chain.Options{
		DataDir:        dataDir,
		MinPowBits:     1,
		GenesisAddress: wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG(bootstrap) error = %v", err)
	}

	// Step 0: Spend genesis UTXO to split total supply into 100 mature outputs
	genesisUTXO := bootstrap.GetUTXOs(wallet.address)[0]
	const numSplit = 100
	splitOutputs := make([]chain.TxOutput, numSplit)
	valPerOut := chain.TotalSupply / numSplit
	for i := 0; i < numSplit-1; i++ {
		splitOutputs[i] = chain.TxOutput{Address: wallet.address, Value: valPerOut}
	}
	splitOutputs[numSplit-1] = chain.TxOutput{Address: wallet.address, Value: chain.TotalSupply - valPerOut*int64(numSplit-1)}

	seedTx := &chain.Transaction{
		Parents:   []string{bootstrap.GenesisID(), bootstrap.GenesisID()},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   splitOutputs,
		Timestamp: time.Now().Unix() - chain.MinUTXOMaturitySeconds - 100,
	}
	wallet.sign(t, seedTx, 0, genesisUTXO)
	mineWithDAG(t, bootstrap, seedTx, 1)
	if err := bootstrap.SubmitTx(seedTx); err != nil {
		t.Fatalf("SubmitTx(seedSplit) error = %v", err)
	}

	startTimestamp := time.Now().Unix() - chain.PowCongestionWindowSeconds
	utxos := bootstrap.GetUTXOs(wallet.address)
	for offset := int64(0); offset <= chain.PowCongestionWindowSeconds; offset++ {
		if int(offset) >= len(utxos) {
			break
		}
		spendable := utxos[offset]
		tip1, tip2 := bootstrap.SelectTips()
		tx := &chain.Transaction{
			Parents:   []string{tip1, tip2},
			Inputs:    []chain.TxInput{{TxID: spendable.TxID, Index: spendable.Index}},
			Outputs:   []chain.TxOutput{{Address: wallet.address, Value: spendable.Value}},
			Timestamp: startTimestamp + offset,
		}
		wallet.sign(t, tx, 0, spendable)
		mineWithDAG(t, bootstrap, tx, 1)
		if err := bootstrap.SubmitTx(tx); err != nil {
			t.Fatalf("SubmitTx(congestion seed) error = %v", err)
		}
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatalf("bootstrap.Close() error = %v", err)
	}

	dag, err := chain.NewDAG(chain.Options{DataDir: dataDir, GenesisAddress: wallet.address})
	if err != nil {
		t.Fatalf("NewDAG(reload) error = %v", err)
	}
	t.Cleanup(func() { _ = dag.Close() })
	return dag
}

func newUnderMinedCongestionTx(t *testing.T, dag *chain.DAG, sender testWallet, receiver testWallet) (*chain.Transaction, int) {
	t.Helper()

	spendable := dag.GetUTXOs(sender.address)[0]
	tip1, tip2 := dag.SelectTips()
	parent := dag.GetTransaction(tip1)
	if parent == nil {
		t.Fatal("expected parent tip to exist")
	}
	tx := &chain.Transaction{
		Parents:   []string{tip1, tip2},
		Inputs:    []chain.TxInput{{TxID: spendable.TxID, Index: spendable.Index}},
		Outputs:   []chain.TxOutput{{Address: receiver.address, Value: spendable.Value}},
		Timestamp: parent.Timestamp,
	}
	sender.sign(t, tx, 0, spendable)
	// Fill parent PoW hashes so the commitment is satisfied; we then search for
	// a nonce that meets base bits but NOT the higher congestion requirement.
	if err := dag.FillParentPowHashes(tx); err != nil {
		t.Fatalf("FillParentPowHashes() error = %v", err)
	}
	requiredBits, err := dag.RequiredPowBits(tx)
	if err != nil {
		t.Fatalf("RequiredPowBits() error = %v", err)
	}
	foundNonce := false
	for nonce := int64(0); nonce < 1_000_000; nonce++ {
		tx.PowNonce = nonce
		meetsBase, err := chain.TxMeetsWork(tx, chain.BaseTxWorkBits)
		if err != nil {
			t.Fatalf("TxMeetsWork(base) error = %v", err)
		}
		if !meetsBase {
			continue
		}
		meetsRequired, err := chain.TxMeetsWork(tx, requiredBits)
		if err != nil {
			t.Fatalf("TxMeetsWork(required) error = %v", err)
		}
		if meetsRequired {
			continue
		}
		foundNonce = true
		break
	}
	if !foundNonce {
		t.Fatalf("failed to find nonce that meets base %d bits but stays below required %d bits", chain.BaseTxWorkBits, requiredBits)
	}
	tx.PowBits = chain.BaseTxWorkBits
	tx.ID = strings.Repeat("f", 64)
	return tx, requiredBits
}

func newTestDAGWithGenesis(t *testing.T, genesisAddr string) *chain.DAG {
	t.Helper()
	dag, err := chain.NewDAG(chain.Options{
		DataDir:        t.TempDir(),
		MinPowBits:     1,
		GenesisAddress: genesisAddr,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}
	t.Cleanup(func() { _ = dag.Close() })
	return dag
}

func writeSyncResponse(w http.ResponseWriter, r *http.Request, ordered []chain.Transaction) {
	var req syncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > syncBatchLimit {
		limit = syncBatchLimit
	}

	idxOf := make(map[string]int, len(ordered))
	for i, tx := range ordered {
		idxOf[tx.ID] = i
	}

	commonBaseID := ""
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; ok {
			commonBaseID = haveID
			break
		}
	}

	var want []string
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; !ok {
			want = append(want, haveID)
		}
	}
	if want == nil {
		want = []string{}
	}

	clientKnown := make(map[string]bool, len(ordered))
	for _, haveID := range req.Have {
		if _, ok := idxOf[haveID]; ok {
			markAncestorClosure(haveID, clientKnown, idxOf, ordered)
		}
	}

	tips := []string{}
	if len(ordered) > 0 {
		tips = append(tips, ordered[len(ordered)-1].ID)
	}
	needed := make(map[string]bool)
	for _, tip := range tips {
		markAncestorClosure(tip, needed, idxOf, ordered)
	}
	for id := range clientKnown {
		delete(needed, id)
	}

	var missing []chain.Transaction
	for _, tx := range ordered {
		if needed[tx.ID] {
			missing = append(missing, tx)
		}
	}

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

	_ = json.NewEncoder(w).Encode(syncResponse{
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

func mustStringSlice(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			panic("expected string item")
		}
		out = append(out, s)
	}
	return out
}

func newSyncTestServer(t *testing.T, n *Node) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(n.routes())
	n.onionPublicURL = server.URL
	t.Cleanup(server.Close)
	return server
}

type testWallet struct {
	privateKey   sign.PrivateKey
	publicKeyHex string
	address      string
}

func newTestWallet(t *testing.T) testWallet {
	t.Helper()

	scheme := mldsa87.Scheme()
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	pubHex := hex.EncodeToString(pubBytes)
	address, err := chain.PolicyAddress(1, []string{pubHex})
	if err != nil {
		t.Fatalf("PolicyAddress() error = %v", err)
	}
	return testWallet{
		privateKey:   priv,
		publicKeyHex: pubHex,
		address:      address,
	}
}

func (w testWallet) sign(t *testing.T, tx *chain.Transaction, inputIndex int, spentUTXO *chain.UTXO) {
	t.Helper()

	scheme := mldsa87.Scheme()
	payload := chain.SigningPayload(tx, inputIndex, spentUTXO)
	sig := scheme.Sign(w.privateKey, payload, nil)
	tx.Inputs[inputIndex].Witness = &chain.TxWitness{
		Type: chain.WitnessTypeThreshold,
		Threshold: &chain.ThresholdWitness{
			Threshold:  1,
			PublicKeys: []string{w.publicKeyHex},
			Signatures: []string{hex.EncodeToString(sig)},
		},
	}
}

func toAnySlice(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

// mineWithDAG fills parent PoW hashes (tips commitment) and mines the PoW nonce.
// Always use this instead of chain.MineTxPoW directly in node tests so that
// tx.ParentPowHashes is correctly populated before mining.
func appendLinearTestTxs(t *testing.T, dag *chain.DAG, sender, receiver testWallet, count int) []string {
	t.Helper()

	// Step 0: Spend genesis UTXO to split total supply into count mature outputs
	genesisUTXO := dag.GetUTXOs(sender.address)[0]
	splitOutputs := make([]chain.TxOutput, count)
	valPerOut := genesisUTXO.Value / int64(count)
	for i := 0; i < count-1; i++ {
		splitOutputs[i] = chain.TxOutput{Address: sender.address, Value: valPerOut}
	}
	splitOutputs[count-1] = chain.TxOutput{Address: sender.address, Value: genesisUTXO.Value - valPerOut*int64(count-1)}

	baseTime := time.Now().Unix() - chain.MinUTXOMaturitySeconds - 100
	seedTx := &chain.Transaction{
		Parents:   []string{dag.GenesisID(), dag.GenesisID()},
		Inputs:    []chain.TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   splitOutputs,
		Timestamp: baseTime,
	}
	sender.sign(t, seedTx, 0, genesisUTXO)
	mineWithDAG(t, dag, seedTx, 1)
	if err := dag.SubmitTx(seedTx); err != nil {
		t.Fatalf("SubmitTx(seedSplit) error = %v", err)
	}

	ids := make([]string, 0, count)
	utxos := dag.GetUTXOs(sender.address)
	for i := 0; i < count; i++ {
		spendable := utxos[i]
		tip1, tip2 := dag.SelectTips()
		tx := &chain.Transaction{
			Parents:   []string{tip1, tip2},
			Inputs:    []chain.TxInput{{TxID: spendable.TxID, Index: spendable.Index}},
			Outputs:   []chain.TxOutput{{Address: receiver.address, Value: spendable.Value}},
			Timestamp: baseTime + chain.MinUTXOMaturitySeconds + int64(i+1),
		}
		sender.sign(t, tx, 0, spendable)
		mineWithDAG(t, dag, tx, 1)
		if err := dag.SubmitTx(tx); err != nil {
			t.Fatalf("SubmitTx() error = %v", err)
		}
		ids = append(ids, tx.ID)
	}
	return ids
}

func mineWithDAG(t *testing.T, dag *chain.DAG, tx *chain.Transaction, bits int) {
	t.Helper()
	if err := dag.FillParentPowHashes(tx); err != nil {
		t.Fatalf("FillParentPowHashes() error = %v", err)
	}
	if err := chain.MineTxPoW(context.Background(), tx, bits); err != nil {
		t.Fatalf("MineTxPoW() error = %v", err)
	}
}
