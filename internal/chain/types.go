package chain

// TxInput references a UTXO to be spent in a transaction.
type TxInput struct {
	TxID    string     `json:"txid"`
	Index   int        `json:"index"`
	Witness *TxWitness `json:"witness,omitempty"`
}

// TxWitness authorizes spending of an input.
type TxWitness struct {
	Type      string            `json:"type"`
	Threshold *ThresholdWitness `json:"threshold,omitempty"`
}

// ThresholdWitness is an M-of-N ML-DSA-87 threshold signature witness.
// PublicKeys contains all policy keys in sorted, lowercase hex order.
// Signatures is parallel to PublicKeys: the hex-encoded ML-DSA-87 signature
// for that key, or the empty string if that key did not sign this input.
type ThresholdWitness struct {
	Threshold  int      `json:"threshold"`
	PublicKeys []string `json:"public_keys"`
	Signatures []string `json:"signatures"`
}

// TxOutput describes a new UTXO created by a transaction.
type TxOutput struct {
	Address string `json:"address"`
	Value   int64  `json:"value"` // in chillar (1 SIKKA = 10_000_000_000 chillar)
}

// Transaction is a node in the Sikka DAG.
// Parents holds exactly 2 tx IDs (empty only for genesis).
// Inputs is empty only for genesis.
// PowBits is the number of leading zero bits achieved in the PoW hash.
// ParentPowHashes holds the hex-encoded SHA3-256 PoW hashes of the two parent
// transactions at the time of mining. This commits the PoW work to a specific
// DAG state, preventing selfish mining (pre-mining against stale tips is wasted
// work because the parent PoW hashes won't match the current DAG state).
// WitnessStripped is set to true after the Deep Finality Guard (180 days +
// weight ≥ 1000) triggers and the ML-DSA-87 signature bytes are permanently
// deleted from this transaction's inputs. Syncing nodes must not treat absent
// witness data as corruption when this flag is true.
type Transaction struct {
	ID              string     `json:"id"`
	Parents         []string   `json:"parents"`
	ParentPowHashes []string   `json:"parent_pow_hashes,omitempty"`
	Inputs          []TxInput  `json:"inputs"`
	Outputs         []TxOutput `json:"outputs"`
	PowNonce        int64      `json:"pow_nonce"`
	PowBits         int        `json:"pow_bits"`
	Timestamp       int64      `json:"timestamp"`
	WitnessStripped bool       `json:"witness_stripped,omitempty"`
}


// UTXO is an unspent transaction output.
type UTXO struct {
	TxID      string `json:"txid"`
	Index     int    `json:"index"`
	Address   string `json:"address"`
	Value     int64  `json:"value"`      // in chillar
	DAGDepth  int64  `json:"dag_depth"`  // longest path from genesis to the tx that created this UTXO
	CreatedAt int64  `json:"created_at"` // Unix timestamp of the tx that created this UTXO
}
