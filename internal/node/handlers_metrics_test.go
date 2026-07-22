package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"besoeasy/sikka/internal/config"
)

func TestMetricsHandler(t *testing.T) {
	node, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	node.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") || !strings.Contains(contentType, "version=0.0.4") {
		t.Errorf("unexpected content type: %q", contentType)
	}

	body := rec.Body.String()
	expectedMetrics := []string{
		"sikka_tor_peers_connected",
		"sikka_tor_control_connected",
		"sikka_tor_circuit_established",
		"sikka_tor_bootstrap_progress_percent",
		"sikka_dag_tip_count",
		"sikka_dag_tx_total",
		"sikka_dag_max_depth",
		"sikka_dag_total_pow_weight",
		"sikka_dag_max_tip_weight",
		"sikka_dag_utxo_count",
		"sikka_mempool_size",
		"sikka_dag_confirmed_tx_count",
		"sikka_tx_ingested_total",
		"sikka_tx_ingestion_rate_1m",
		"sikka_tx_ingestion_rate_5m",
		"sikka_process_goroutines",
		"sikka_process_cpu_count",
		"sikka_process_memory_alloc_bytes",
		"sikka_process_memory_sys_bytes",
		"sikka_process_memory_heap_alloc_bytes",
		"sikka_process_memory_heap_sys_bytes",
		"sikka_process_memory_heap_objects",
		"sikka_process_memory_gc_cycles_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics response missing expected metric: %s", metric)
		}
	}
}
