package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGETDAGTipsRoute(t *testing.T) {
	n := testNodeWithPeers(t)
	handler := n.routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/dag/tips", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/dag/tips status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if _, ok := resp["tips"]; !ok {
		t.Errorf("missing 'tips' field in response")
	}
	if _, ok := resp["tip_count"]; !ok {
		t.Errorf("missing 'tip_count' field in response")
	}
}

func TestGETPeersRoute(t *testing.T) {
	n := testNodeWithPeers(t)
	handler := n.routes()

	_, _, _ = n.addKnownNode("http://peer1.sikka:74552", false, false)
	n.penalizeNode("http://badpeer.sikka:74552", 100, "banned by test")

	req := httptest.NewRequest(http.MethodGet, "/v1/peers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/peers status = %d, want 200", rec.Code)
	}

	var resp peerTelemetryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if resp.TotalKnown < 2 {
		t.Errorf("expected total_known >= 2, got %d", resp.TotalKnown)
	}
	if resp.BannedCount != 1 {
		t.Errorf("expected banned_count = 1, got %d", resp.BannedCount)
	}
}

func TestGETAddressHistoryRoute(t *testing.T) {
	n := testNodeWithPeers(t)
	handler := n.routes()

	// Genesis address
	genesisAddr := "sikka1pd6hpxxz9664h4h3scf8cazdlan33srrg4myywla382avn75rn0fsr537k6"
	req := httptest.NewRequest(http.MethodGet, "/v1/address/"+genesisAddr+"/history", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/address/{addr}/history status = %d, want 200", rec.Code)
	}

	var resp addressHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if resp.Address != genesisAddr {
		t.Errorf("address mismatch: got %s, want %s", resp.Address, genesisAddr)
	}
	if resp.Count != 1 {
		t.Errorf("expected 1 history tx for genesis, got %d", resp.Count)
	}
}
