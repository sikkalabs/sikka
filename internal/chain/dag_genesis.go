//go:build !js

package chain

import (
	"fmt"
)

// buildGenesisTx returns the genesis transaction.
// genesisAddr is the address that receives TotalSupply.
// If empty, the network default genesis address is used.
func buildGenesisTx(genesisAddr string) *Transaction {
	if genesisAddr == "" {
		genesisAddr = genesisAddress()
	}
	tx := &Transaction{
		Parents:   []string{},
		Inputs:    []TxInput{},
		Outputs:   []TxOutput{{Address: genesisAddr, Value: TotalSupply}},
		PowNonce:  0,
		PowBits:   0,
		Timestamp: GenesisTimestamp,
	}
	tx.ID = computeTxID(tx)
	return tx
}

// genesisAddress returns the address that receives TotalSupply in the genesis tx.
func genesisAddress() string {
	return "sikka1pd6hpxxz9664h4h3scf8cazdlan33srrg4myywla382avn75rn0fsr537k6"
}

// DefaultGenesisAddress is the network genesis funding address used when a DAG
// is created without an explicit GenesisAddress option.
func DefaultGenesisAddress() string {
	return genesisAddress()
}

// Compile-time guard: the hardcoded genesis address must be a valid bech32m
// address. A typo here would silently mint TotalSupply into an unspendable
// address (genesis bypasses validateTxLocked), so we fail-fast at package init.
func init() {
	normalized, err := NormalizeAddress(genesisAddress())
	if err != nil {
		panic(fmt.Sprintf("chain: hardcoded genesis address is invalid: %v", err))
	}
	if normalized != genesisAddress() {
		panic(fmt.Sprintf("chain: hardcoded genesis address %q is not canonical (want %q)", genesisAddress(), normalized))
	}
}
