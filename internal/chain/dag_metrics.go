//go:build !js

package chain

import "time"

// TotalPoWWeight returns the sum of cumulative PoW weights across all active tips.
func (d *DAG) TotalPoWWeight() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var total int64
	for tip := range d.tips {
		total += d.txWeightLocked(tip)
	}
	return total
}

// MaxTipWeight returns the highest cumulative PoW weight among active tips.
func (d *DAG) MaxTipWeight() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var maxW int64
	for tip := range d.tips {
		if w := d.txWeightLocked(tip); w > maxW {
			maxW = w
		}
	}
	return maxW
}

// UnconfirmedCount returns the number of transactions whose weight is below confirmation threshold.
func (d *DAG) UnconfirmedCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for id := range d.txs {
		if d.txWeightLocked(id) < d.confirmationThreshold {
			count++
		}
	}
	return count
}

// ConfirmedCount returns the number of transactions whose weight meets or exceeds confirmation threshold.
func (d *DAG) ConfirmedCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for id := range d.txs {
		if d.txWeightLocked(id) >= d.confirmationThreshold {
			count++
		}
	}
	return count
}

// UTXOCount returns the total number of created UTXOs in the DAG.
func (d *DAG) UTXOCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.utxos)
}

// IngestedTxCount returns the total number of ingested transactions.
func (d *DAG) IngestedTxCount() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ingestedCount
}

// IngestionRate returns the average transaction ingestion rate (tx/sec) over windowSeconds.
func (d *DAG) IngestionRate(windowSeconds int64) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if windowSeconds <= 0 {
		return 0.0
	}
	now := time.Now().Unix()
	cutoff := now - windowSeconds
	pruneCutoff := now - 300

	validIdx := -1
	for i, t := range d.ingestHistory {
		if t >= pruneCutoff {
			validIdx = i
			break
		}
	}
	if validIdx > 0 {
		d.ingestHistory = append([]int64(nil), d.ingestHistory[validIdx:]...)
	} else if validIdx == -1 && len(d.ingestHistory) > 0 {
		d.ingestHistory = nil
	}

	count := 0
	for _, t := range d.ingestHistory {
		if t >= cutoff {
			count++
		}
	}
	return float64(count) / float64(windowSeconds)
}
