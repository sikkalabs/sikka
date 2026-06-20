package chain

import (
	"fmt"
)

const (
	// SubunitsPerSikka is the number of chillar in one SIKKA (10 decimal places).
	SubunitsPerSikka = int64(10_000_000_000)

	// TotalSupply is the fixed supply of SIKKA in chillar. Encodes the founder's
	// birthday in ISO 8601 (YYYYMMDD = 19960907). Fits comfortably in int64.
	TotalSupply = int64(19_960_907) * SubunitsPerSikka

	// DefaultConfirmationThreshold is the cumulative PoW weight at which a tx
	// is considered confirmed. Config parameter, not a hard constant.
	DefaultConfirmationThreshold = int64(200)

	// MaxTxInputs is the maximum number of inputs a transfer tx may have.
	MaxTxInputs = 64

	// MaxTxOutputs is the maximum number of outputs a transfer tx may have.
	MaxTxOutputs = 256

	// GenesisTimestamp is the Unix timestamp of the Sikka genesis tx.
	// 1996-09-07 00:00:00 IST (UTC+5:30).
	GenesisTimestamp = int64(841353000)

	// BaseTxWorkBits is the minimum PoW requirement before congestion surcharges.
	BaseTxWorkBits = 2

	// PowCongestionWindowSeconds is the recent-history window used for congestion pricing.
	PowCongestionWindowSeconds = int64(60)

	// PowTargetTransactionsPerSecond is the target throughput before congestion surcharges.
	PowTargetTransactionsPerSecond = 1

	// PowCongestionBucketTransactions is the number of extra recent transactions that triggers
	// the next congestion bucket.
	PowCongestionBucketTransactions = PowTargetTransactionsPerSecond * int(PowCongestionWindowSeconds)

	// PowCongestionBucketBits adds 2 bits per congestion bucket, which is 4x expected work.
	PowCongestionBucketBits = 2

	// MaxFutureSkewSeconds is the maximum allowed future timestamp skew for submitted transactions.
	MaxFutureSkewSeconds = int64(5 * 60)

	// ConflictPruneGraceSeconds is how long losing spends are kept after the
	// canonical winner is confirmed and leads by ConflictPruneWeightLead.
	// Sixteen congestion windows (16 × 60s = 16 minutes) gives Tor-slow peers
	// time to sync competing txs before losers are physically removed.
	ConflictPruneGraceSeconds = 16 * PowCongestionWindowSeconds

	// MinUTXOMaturitySeconds is the minimum wall-clock age (in Unix seconds) a
	// UTXO must reach before it can be spent. Uses tx.Timestamp, which is
	// committed into the PoW hash and cannot be faked more than
	// MaxFutureSkewSeconds (5 min). Prevents instant-spend-on-receive and
	// stockpile-and-dump spam attacks.
	//
	// Set to 2× MaxFutureSkewSeconds so the future-timestamp bypass shaves at
	// most half the window, always leaving ≥5 min of genuine ageing.
	MinUTXOMaturitySeconds = int64(600)

	// weightSaturationFactor caps cumulative weight propagation at
	// confirmationThreshold * weightSaturationFactor. Once an ancestor's
	// cumulative weight reaches saturation, further descendants stop
	// propagating weight to it (and, by the weight[parent] >= weight[child]
	// invariant, to any of its ancestors). This keeps SubmitTx work O(active
	// frontier) instead of O(chain size) without changing IsConfirmed answers:
	// saturation is many multiples of the confirmation threshold, so all
	// honest nodes still agree on the confirmed/unconfirmed boundary.
	weightSaturationFactor = int64(16)

	// recentAncestorCountSafetyCap is a hard upper bound on the number of
	// ancestors traversed by recentAncestorCountLocked. The walk already
	// short-circuits when an ancestor's timestamp falls outside the
	// congestion window, but a malformed chain (e.g. clock-skewed parents)
	// could otherwise force an unbounded scan during PoW quoting.
	recentAncestorCountSafetyCap = 100_000

	// WitnessMinWeight is the minimum cumulative PoW weight a transaction
	// must have accumulated before its ML-DSA-87 witness bytes are eligible
	// for stripping. Set to 5× the default confirmation threshold.
	// Both WitnessMinWeight AND WitnessMinAgeSecs must be satisfied before
	// any stripping occurs (Deep Finality Guard — dual-condition).
	WitnessMinWeight = int64(1000)

	// WitnessMinAgeSecs is the minimum wall-clock age (in seconds) a
	// transaction must reach before its witness bytes are eligible for
	// stripping. Defaults to 180 days — a conservative launch-phase window
	// that gives new nodes ample time to bootstrap full history and ensures
	// the honest network has built substantial weight before any signature
	// data is permanently deleted.
	// Both WitnessMinWeight AND WitnessMinAgeSecs must be satisfied.
	WitnessMinAgeSecs = int64(180 * 24 * 60 * 60) // 180 days

	// WeightCompactionDepth is the number of epochs (1 epoch = 10k depth)
	// behind the active DAG frontier beyond which cumulative weight indices
	// are permanently deleted from memory and disk. Since deep transactions
	// have saturated weights that never change, their weight can be implicitly
	// inferred, saving massive index space. Set to 10 epochs (100,000 txs).
	WeightCompactionDepth = int64(100_000)
)

// FormatSikka formats a chillar amount as a human-readable SIKKA string.
func FormatSikka(chillar int64) string {
	whole := chillar / SubunitsPerSikka
	frac := chillar % SubunitsPerSikka
	if frac < 0 {
		frac = -frac
	}
	return fmt.Sprintf("%d.%010d", whole, frac)
}

// utxoKey returns the canonical string key for a UTXO.
func utxoKey(txid string, index int) string {
	return fmt.Sprintf("%s:%d", txid, index)
}

// txPowLeadingZeroBits counts the number of leading zero bits in the
// SHA3-256 PoW hash of tx. Returns the leading zero bit count, or an error.
func txPowLeadingZeroBits(tx *Transaction) (int, error) {
	hash, err := txPowHash(tx)
	if err != nil {
		return 0, err
	}
	return leadingZeroBits(hash[:]), nil
}

// leadingZeroBits counts the number of leading zero bits in a byte slice.
func leadingZeroBits(b []byte) int {
	count := 0
	for _, byt := range b {
		if byt == 0 {
			count += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if byt&(1<<uint(bit)) != 0 {
				return count
			}
			count++
		}
		break
	}
	return count
}

// txMeetsMinPowBits returns true if tx's PoW hash has at least minBits leading
// zero bits.
func txMeetsMinPowBits(tx *Transaction, minBits int) (bool, error) {
	bits, err := txPowLeadingZeroBits(tx)
	if err != nil {
		return false, err
	}
	return bits >= minBits, nil
}

// TxMeetsWork is the exported wrapper for txMeetsMinPowBits.
func TxMeetsWork(tx *Transaction, minBits int) (bool, error) {
	return txMeetsMinPowBits(tx, minBits)
}

// cloneTransaction returns a shallow copy of a Transaction.
func cloneTransaction(tx *Transaction) *Transaction {
	if tx == nil {
		return nil
	}
	cp := *tx
	if tx.Parents != nil {
		cp.Parents = append([]string(nil), tx.Parents...)
	}
	if tx.Inputs != nil {
		cp.Inputs = append([]TxInput(nil), tx.Inputs...)
	}
	if tx.Outputs != nil {
		cp.Outputs = append([]TxOutput(nil), tx.Outputs...)
	}
	return &cp
}

// cloneUTXO returns a shallow copy of a UTXO.
func cloneUTXO(u *UTXO) *UTXO {
	if u == nil {
		return nil
	}
	cp := *u
	return &cp
}
