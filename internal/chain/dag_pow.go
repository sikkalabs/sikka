//go:build !js

package chain

import (
	"fmt"
	"time"
)

func (d *DAG) quoteTxPoWLocked(tx *Transaction) (TxPowQuote, error) {
	if tx == nil {
		return TxPowQuote{}, fmt.Errorf("transaction is required")
	}
	if len(tx.Parents) != 2 {
		return TxPowQuote{}, fmt.Errorf("transaction must have exactly 2 parents, got %d", len(tx.Parents))
	}
	// For quoting we only need parents to exist and timestamps to be valid.
	// The ParentPowHashes commitment check is enforced at submission time only.
	if err := d.validateParentsExistAndTimestampLocked(tx); err != nil {
		return TxPowQuote{}, err
	}

	// Compute parent PoW hashes so that wallet miners can commit to the exact
	// current tips (tips commitment). These must be passed through mining and
	// submission; using stale values will cause the submitted tx to be rejected.
	hashes := make([]string, len(tx.Parents))
	for i, parentID := range tx.Parents {
		parent := d.getTransactionLocked(parentID)
		// Existence already validated above.
		h, err := txPowHash(parent)
		if err != nil {
			return TxPowQuote{}, fmt.Errorf("parent %s pow hash: %w", parentID, err)
		}
		hashes[i] = fmt.Sprintf("%x", h)
	}

	quote := TxPowQuote{
		BaseBits:        BaseTxWorkBits,
		WindowSeconds:   PowCongestionWindowSeconds,
		BucketTx:        PowCongestionBucketTransactions,
		BucketBits:      PowCongestionBucketBits,
		ParentPowHashes: hashes,
	}
	// Also attach to the input tx for callers that expect Fill-like behavior.
	tx.ParentPowHashes = hashes

	if d.minPowBits > 0 {
		quote.RequiredBits = d.minPowBits
		quote.OverrideBits = d.minPowBits
		return quote, nil
	}
	recentCount := d.recentAncestorCountLocked(tx)
	extraBuckets := 0
	if recentCount > PowCongestionBucketTransactions {
		remaining := recentCount - PowCongestionBucketTransactions
		extraBuckets = (remaining + PowCongestionBucketTransactions - 1) / PowCongestionBucketTransactions
	}
	quote.RecentCount = recentCount
	quote.CongestionBuckets = extraBuckets
	quote.RequiredBits = BaseTxWorkBits + extraBuckets*PowCongestionBucketBits
	return quote, nil
}

// validateParentsExistAndTimestampLocked checks parent existence, hex format,
// and timestamp ordering. Used by the PoW quote path which runs before mining
// (so ParentPowHashes is not yet populated). The full ParentPowHashes commitment
// check is done in validateTimestampAndParentsLocked at submission time.
func (d *DAG) validateParentsExistAndTimestampLocked(tx *Transaction) error {
	if tx.Timestamp == 0 {
		return fmt.Errorf("timestamp is required (must be set before mining)")
	}
	now := time.Now().Unix()
	if tx.Timestamp > now+MaxFutureSkewSeconds {
		return fmt.Errorf("timestamp %d is too far in the future", tx.Timestamp)
	}
	maxParentTimestamp := int64(0)
	for _, parentID := range tx.Parents {
		if len(parentID) != 64 {
			return fmt.Errorf("parent tx id %q is not a valid 64-char hex string", parentID)
		}
		parent := d.getTransactionLocked(parentID)
		if parent == nil {
			return fmt.Errorf("parent tx %s not found", parentID)
		}
		if parent.Timestamp > maxParentTimestamp {
			maxParentTimestamp = parent.Timestamp
		}
	}
	if tx.Timestamp < maxParentTimestamp {
		return fmt.Errorf("timestamp %d is older than newest parent timestamp %d", tx.Timestamp, maxParentTimestamp)
	}
	return nil
}

func (d *DAG) recentAncestorCountLocked(tx *Transaction) int {
	windowStart := tx.Timestamp - PowCongestionWindowSeconds
	stack := append([]string(nil), tx.Parents...)
	visited := make(map[string]bool, len(stack))
	count := 0
	for len(stack) > 0 {
		if count >= recentAncestorCountSafetyCap {
			// Hard cap: the timestamp window already short-circuits the walk
			// in normal operation, but a misformed chain (clock-skewed
			// parents) could otherwise cause an unbounded scan. Return the
			// cap; PoW quoting will simply demand the maximum congestion
			// surcharge for this candidate.
			return count
		}
		last := len(stack) - 1
		txid := stack[last]
		stack = stack[:last]
		if visited[txid] {
			continue
		}
		visited[txid] = true
		ancestor := d.getTransactionLocked(txid)
		if ancestor == nil {
			continue
		}
		if ancestor.Timestamp < windowStart {
			continue
		}
		count++
		stack = append(stack, ancestor.Parents...)
	}
	return count
}

// RequiredPowBits returns the current minimum PoW bits for a candidate transaction.
func (d *DAG) RequiredPowBits(tx *Transaction) (int, error) {
	quote, err := d.QuoteTxPoW(tx)
	if err != nil {
		return 0, err
	}
	return quote.RequiredBits, nil
}

// MinPowBitsOverride returns the fixed override bits, if any.
func (d *DAG) MinPowBitsOverride() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.minPowBits
}
