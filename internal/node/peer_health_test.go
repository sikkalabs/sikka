package node

import (
	"testing"
	"time"

	"besoeasy/sikka/internal/config"
)

func testNodeWithPeers(t *testing.T) *Node {
	t.Helper()
	cfg := config.Config{
		DataDir: t.TempDir(),
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	return n
}

func TestPeerLatencyEMA(t *testing.T) {
	n := testNodeWithPeers(t)

	peerURL := "http://peer1.sikka:74552"
	_, _, err := n.addKnownNode(peerURL, false, false)
	if err != nil {
		t.Fatalf("addKnownNode failed: %v", err)
	}

	// Record initial latency
	n.recordPeerLatency(peerURL, 100*time.Millisecond)

	n.nodeBookMu.RLock()
	_, record, state := n.findKnownNodeByAddressLocked(peerURL)
	n.nodeBookMu.RUnlock()

	if record == nil || state == nil {
		t.Fatalf("expected node record and state")
	}
	if state.latencyEMA != 100*time.Millisecond {
		t.Errorf("expected initial EMA 100ms, got %v", state.latencyEMA)
	}

	// Record second latency sample (200ms)
	// EMA formula: 0.2 * 200ms + 0.8 * 100ms = 40ms + 80ms = 120ms
	n.recordPeerLatency(peerURL, 200*time.Millisecond)

	n.nodeBookMu.RLock()
	_, _, state = n.findKnownNodeByAddressLocked(peerURL)
	n.nodeBookMu.RUnlock()

	if state.latencyEMA != 120*time.Millisecond {
		t.Errorf("expected updated EMA 120ms, got %v", state.latencyEMA)
	}
}

func TestPeerPenalizeAndBan(t *testing.T) {
	n := testNodeWithPeers(t)

	peerURL := "http://badpeer.sikka:74552"
	_, _, err := n.addKnownNode(peerURL, false, false)
	if err != nil {
		t.Fatalf("addKnownNode failed: %v", err)
	}

	// Penalize below threshold
	n.penalizeNode(peerURL, 50, "test minor violation")

	n.nodeBookMu.RLock()
	_, record, _ := n.findKnownNodeByAddressLocked(peerURL)
	n.nodeBookMu.RUnlock()

	if record.banScore != 50 {
		t.Errorf("expected banScore 50, got %d", record.banScore)
	}
	if !record.bannedUntil.IsZero() {
		t.Errorf("expected node not yet banned")
	}

	// Penalize above max threshold (100)
	n.penalizeNode(peerURL, 60, "test major violation")

	now := time.Now()
	n.nodeBookMu.RLock()
	_, record, _ = n.findKnownNodeByAddressLocked(peerURL)
	n.nodeBookMu.RUnlock()

	if record.banScore != 110 {
		t.Errorf("expected banScore 110, got %d", record.banScore)
	}
	if record.bannedUntil.IsZero() || record.bannedUntil.Before(now) {
		t.Errorf("expected node to be banned until future time, got %v", record.bannedUntil)
	}

	// Verify selectPeerAddress excludes banned node
	selected := n.selectPeerAddress(record, now, true)
	if selected != "" {
		t.Errorf("expected empty address for banned node, got %s", selected)
	}

	// Test unban
	n.unbanNode(peerURL)
	n.nodeBookMu.RLock()
	_, record, _ = n.findKnownNodeByAddressLocked(peerURL)
	n.nodeBookMu.RUnlock()

	if record.banScore != 0 || !record.bannedUntil.IsZero() {
		t.Errorf("expected node to be unbanned, got score=%d, bannedUntil=%v", record.banScore, record.bannedUntil)
	}
}
