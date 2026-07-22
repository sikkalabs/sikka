package node

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

func (n *Node) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	torStatus := n.torStatusPayload()
	controlConnected := 0
	if cc, ok := torStatus["control_connected"].(bool); ok && cc {
		controlConnected = 1
	}
	circuitEstablished := 0
	if ce, ok := torStatus["circuit_established"].(bool); ok && ce {
		circuitEstablished = 1
	}
	bootstrapProgress := 0
	if bp, ok := torStatus["bootstrap_progress"].(int); ok {
		bootstrapProgress = bp
	}

	knownPeers := n.knownNodeCount()
	tips := n.localSyncDAGTips()
	tipCount := len(tips)
	dagSize := n.dag.Size()
	maxDepth := n.dag.MaxDepth()
	totalPowWeight := n.dag.TotalPoWWeight()
	maxTipWeight := n.dag.MaxTipWeight()
	utxoCount := n.dag.UTXOCount()
	mempoolSize := n.dag.UnconfirmedCount()
	confirmedCount := n.dag.ConfirmedCount()
	ingestedTotal := n.dag.IngestedTxCount()
	rate1m := n.dag.IngestionRate(60)
	rate5m := n.dag.IngestionRate(300)

	var sb strings.Builder

	writeGauge := func(name, help string, val any) {
		sb.WriteString("# HELP ")
		sb.WriteString(name)
		sb.WriteString(" ")
		sb.WriteString(help)
		sb.WriteString("\n# TYPE ")
		sb.WriteString(name)
		sb.WriteString(" gauge\n")
		sb.WriteString(fmt.Sprintf("%s %v\n\n", name, val))
	}

	writeCounter := func(name, help string, val any) {
		sb.WriteString("# HELP ")
		sb.WriteString(name)
		sb.WriteString(" ")
		sb.WriteString(help)
		sb.WriteString("\n# TYPE ")
		sb.WriteString(name)
		sb.WriteString(" counter\n")
		sb.WriteString(fmt.Sprintf("%s %v\n\n", name, val))
	}

	// Tor & Peer Telemetry
	writeGauge("sikka_tor_peers_connected", "Number of known or active Tor network peers", knownPeers)
	writeGauge("sikka_tor_control_connected", "Status of Tor control socket connection (1=connected, 0=disconnected)", controlConnected)
	writeGauge("sikka_tor_circuit_established", "Status of Tor circuit establishment (1=established, 0=not established)", circuitEstablished)
	writeGauge("sikka_tor_bootstrap_progress_percent", "Percentage of Tor bootstrap progress", bootstrapProgress)

	// DAG Telemetry
	writeGauge("sikka_dag_tip_count", "Number of active DAG tip transactions", tipCount)
	writeGauge("sikka_dag_tx_total", "Total number of transactions in the local DAG", dagSize)
	writeGauge("sikka_dag_max_depth", "Longest depth from genesis in the DAG", maxDepth)
	writeGauge("sikka_dag_total_pow_weight", "Total cumulative PoW weight across DAG tips", totalPowWeight)
	writeGauge("sikka_dag_max_tip_weight", "Highest cumulative PoW weight among active tips", maxTipWeight)
	writeGauge("sikka_dag_utxo_count", "Total number of created unspent transaction outputs", utxoCount)
	writeGauge("sikka_mempool_size", "Number of unconfirmed transactions currently in the DAG", mempoolSize)
	writeGauge("sikka_dag_confirmed_tx_count", "Number of confirmed transactions in the DAG", confirmedCount)

	// Ingestion Telemetry
	writeCounter("sikka_tx_ingested_total", "Total cumulative count of transactions ingested by this node", ingestedTotal)
	writeGauge("sikka_tx_ingestion_rate_1m", "Transaction ingestion rate per second over the last 1 minute", fmt.Sprintf("%.4f", rate1m))
	writeGauge("sikka_tx_ingestion_rate_5m", "Transaction ingestion rate per second over the last 5 minutes", fmt.Sprintf("%.4f", rate5m))

	// Go Runtime & Process Memory Telemetry
	writeGauge("sikka_process_goroutines", "Number of running Go goroutines", runtime.NumGoroutine())
	writeGauge("sikka_process_cpu_count", "Number of logical CPUs available", runtime.NumCPU())
	writeGauge("sikka_process_memory_alloc_bytes", "Bytes of allocated heap objects", m.Alloc)
	writeGauge("sikka_process_memory_sys_bytes", "Total bytes of memory obtained from OS", m.Sys)
	writeGauge("sikka_process_memory_heap_alloc_bytes", "Bytes of allocated heap memory", m.HeapAlloc)
	writeGauge("sikka_process_memory_heap_sys_bytes", "Bytes of heap memory obtained from OS", m.HeapSys)
	writeGauge("sikka_process_memory_heap_objects", "Number of allocated heap objects", m.HeapObjects)
	writeCounter("sikka_process_memory_gc_cycles_total", "Total count of completed GC cycles", m.NumGC)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.WriteString(sb.String())
}
