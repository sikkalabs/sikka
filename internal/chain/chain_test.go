package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign"
)

// ---- test helpers ----

type testWallet struct {
	privKey sign.PrivateKey
	pubKey  sign.PublicKey
	address string
}

func newTestWallet(t *testing.T) testWallet {
	t.Helper()
	scheme := mldsaScheme
	pubKey, privKey, err := scheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	addr, err := policyAddress(1, []string{hex.EncodeToString(pubBytes)})
	if err != nil {
		t.Fatalf("policyAddress() error = %v", err)
	}
	return testWallet{privKey: privKey, pubKey: pubKey, address: addr}
}

func (w *testWallet) pubKeyHex(t *testing.T) string {
	t.Helper()
	b, err := w.pubKey.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return hex.EncodeToString(b)
}

// signInput adds a threshold witness to tx.Inputs[idx] authorised by this wallet.
func (w *testWallet) signInput(t *testing.T, tx *Transaction, idx int, utxo *UTXO) {
	t.Helper()
	payload := signingPayloadBytes(tx, idx, utxo)
	scheme := mldsaScheme
	sig := scheme.Sign(w.privKey, payload, nil)
	pubHex := w.pubKeyHex(t)
	tx.Inputs[idx].Witness = &TxWitness{
		Type: WitnessTypeThreshold,
		Threshold: &ThresholdWitness{
			Threshold:  1,
			PublicKeys: []string{pubHex},
			Signatures: []string{hex.EncodeToString(sig)},
		},
	}
}

// mineTxPow fills parent PoW hashes (tips commitment) and mines the PoW nonce
// for tx using the DAG's requiredPowBits.
func mineTxPow(t *testing.T, dag *DAG, tx *Transaction) {
	t.Helper()
	if err := dag.FillParentPowHashes(tx); err != nil {
		t.Fatalf("FillParentPowHashes() error = %v", err)
	}
	required, err := dag.RequiredPowBits(tx)
	if err != nil {
		t.Fatalf("RequiredPowBits() error = %v", err)
	}
	if err := MineTxPoW(context.Background(), tx, required); err != nil {
		t.Fatalf("MineTxPoW() error = %v", err)
	}
}

// testNewDAG creates a DAG with MinPowBits=1 and genesis going to wallet.
func testNewDAG(t *testing.T, wallet *testWallet) *DAG {
	t.Helper()
	dag, err := NewDAG(Options{
		MinPowBits:     1,
		GenesisAddress: wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}
	return dag
}

// ---- constants tests ----

func TestConstants(t *testing.T) {
	t.Parallel()

	if SubunitsPerSikka != int64(10_000_000_000) {
		t.Errorf("SubunitsPerSikka = %d, want 10_000_000_000", SubunitsPerSikka)
	}
	if TotalSupply != int64(19_960_907)*SubunitsPerSikka {
		t.Errorf("TotalSupply = %d, want 19_960_907 * SubunitsPerSikka", TotalSupply)
	}
	if DefaultConfirmationThreshold <= 0 {
		t.Errorf("DefaultConfirmationThreshold must be positive, got %d", DefaultConfirmationThreshold)
	}
	// Verify no int64 overflow: max int64 = 9.22e18; TotalSupply ≈ 1.996e17
	if TotalSupply <= 0 {
		t.Errorf("TotalSupply overflowed int64: got %d", TotalSupply)
	}
}

func TestFormatSikka(t *testing.T) {
	t.Parallel()

	tests := []struct {
		chillar int64
		want    string
	}{
		{0, "0.0000000000"},
		{1, "0.0000000001"},
		{SubunitsPerSikka, "1.0000000000"},
		{SubunitsPerSikka + 1, "1.0000000001"},
		{TotalSupply, "19960907.0000000000"},
		{-1, "0.0000000001"}, // negative frac normalized to positive
	}
	for _, tt := range tests {
		if got := FormatSikka(tt.chillar); got != tt.want {
			t.Errorf("FormatSikka(%d) = %q, want %q", tt.chillar, got, tt.want)
		}
	}
}

// ---- crypto tests ----

func TestPolicyAddress(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	addr, err := PolicyAddress(1, []string{wallet.pubKeyHex(t)})
	if err != nil {
		t.Fatalf("PolicyAddress() error = %v", err)
	}
	if addr != wallet.address {
		t.Errorf("PolicyAddress mismatch: got %s, want %s", addr, wallet.address)
	}
}

func TestThresholdWitnessRejectsDuplicatePublicKey(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	pubHex := wallet.pubKeyHex(t)
	witness := &ThresholdWitness{
		Threshold:  1,
		PublicKeys: []string{pubHex, pubHex},
		Signatures: []string{"", ""},
	}
	_, err := canonicalizeThresholdPublicKeys(witness.PublicKeys)
	if err == nil {
		t.Fatal("expected error for duplicate public keys, got nil")
	}
}

// ---- DAG tests ----

func TestDAGGenesis(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	if dag.Size() != 1 {
		t.Errorf("Size() = %d, want 1", dag.Size())
	}
	if dag.genesis == "" {
		t.Fatal("genesis tx ID is empty")
	}

	genesis := dag.GetTransaction(dag.genesis)
	if genesis == nil {
		t.Fatal("genesis tx not found")
	}
	if len(genesis.Parents) != 0 {
		t.Errorf("genesis Parents = %v, want []", genesis.Parents)
	}
	if len(genesis.Inputs) != 0 {
		t.Errorf("genesis Inputs = %v, want []", genesis.Inputs)
	}
	if len(genesis.Outputs) != 1 {
		t.Errorf("genesis Outputs len = %d, want 1", len(genesis.Outputs))
	}
	if genesis.Outputs[0].Value != TotalSupply {
		t.Errorf("genesis output value = %d, want %d", genesis.Outputs[0].Value, TotalSupply)
	}
	if genesis.Timestamp != GenesisTimestamp {
		t.Errorf("genesis Timestamp = %d, want %d", genesis.Timestamp, GenesisTimestamp)
	}

	balance := dag.GetBalance(wallet.address)
	if balance != TotalSupply {
		t.Errorf("genesis wallet balance = %d, want %d", balance, TotalSupply)
	}

	tips := dag.Tips()
	if len(tips) != 1 || tips[0] != dag.genesis {
		t.Errorf("Tips() = %v, want [genesis]", tips)
	}
}

func TestDAGSubmitTx(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	wallet2 := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	genesisTxID := dag.genesis
	sendValue := int64(1_000_000_000) // 0.1 SIKKA
	change := TotalSupply - sendValue

	tx := &Transaction{
		Parents: []string{genesisTxID, genesisTxID},
		Inputs:  []TxInput{{TxID: genesisTxID, Index: 0}},
		Outputs: []TxOutput{
			{Address: wallet2.address, Value: sendValue},
			{Address: wallet.address, Value: change},
		},
		Timestamp: time.Now().Unix(),
	}
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}
	wallet.signInput(t, tx, 0, genesisUTXO)
	mineTxPow(t, dag, tx)

	if err := dag.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}
	if tx.ID == "" {
		t.Fatal("tx ID not assigned")
	}

	// Wallet2 should have sendValue, wallet should have change.
	if got := dag.GetBalance(wallet2.address); got != sendValue {
		t.Errorf("wallet2 balance = %d, want %d", got, sendValue)
	}
	if got := dag.GetBalance(wallet.address); got != change {
		t.Errorf("wallet balance = %d, want %d", got, change)
	}

	// DAG should have 2 txs now; new tx should be the only tip.
	if dag.Size() != 2 {
		t.Errorf("Size() = %d, want 2", dag.Size())
	}
	tips := dag.Tips()
	if len(tips) != 1 || tips[0] != tx.ID {
		t.Errorf("Tips() = %v, want [%s]", tips, tx.ID)
	}
}

func TestDAGDoubleSpend(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	bob := newTestWallet(t)
	carol := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	genesisTxID := dag.genesis
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}

	buildTx := func(recipient string, ts int64) *Transaction {
		tx := &Transaction{
			Parents: []string{genesisTxID, genesisTxID},
			Inputs:  []TxInput{{TxID: genesisTxID, Index: 0}},
			Outputs: []TxOutput{
				{Address: recipient, Value: TotalSupply},
			},
			Timestamp: ts,
		}
		wallet.signInput(t, tx, 0, genesisUTXO)
		mineTxPow(t, dag, tx)
		return tx
	}

	now := time.Now().Unix()
	txA := buildTx(bob.address, now)
	txB := buildTx(carol.address, now+1)
	if err := dag.SubmitTx(txA); err != nil {
		t.Fatalf("SubmitTx(txA) error = %v", err)
	}
	if err := dag.SubmitTx(txB); err != nil {
		t.Fatalf("SubmitTx(txB) error = %v", err)
	}
	if dag.Size() != 3 {
		t.Fatalf("Size() = %d, want 3 (genesis + both competing spends)", dag.Size())
	}

	winner := txA.ID
	if spendCandidateBetter(dag.weights, txB.ID, txA.ID) {
		winner = txB.ID
	}
	if winner == txA.ID {
		if got := dag.GetBalance(bob.address); got != TotalSupply {
			t.Fatalf("bob balance = %d, want %d", got, TotalSupply)
		}
		if got := dag.GetBalance(carol.address); got != 0 {
			t.Fatalf("carol balance = %d, want 0", got)
		}
	} else {
		if got := dag.GetBalance(carol.address); got != TotalSupply {
			t.Fatalf("carol balance = %d, want %d", got, TotalSupply)
		}
		if got := dag.GetBalance(bob.address); got != 0 {
			t.Fatalf("bob balance = %d, want 0", got)
		}
	}
}

func TestDAGDoubleSpendConvergesAcrossOrder(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	bob := newTestWallet(t)
	carol := newTestWallet(t)

	dagA := testNewDAG(t, &wallet)
	dagB := testNewDAG(t, &wallet)
	genesisTxID := dagA.genesis
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}

	buildTx := func(dag *DAG, recipient string, ts int64) *Transaction {
		tx := &Transaction{
			Parents: []string{genesisTxID, genesisTxID},
			Inputs:  []TxInput{{TxID: genesisTxID, Index: 0}},
			Outputs: []TxOutput{
				{Address: recipient, Value: TotalSupply},
			},
			Timestamp: ts,
		}
		wallet.signInput(t, tx, 0, genesisUTXO)
		mineTxPow(t, dag, tx)
		return tx
	}

	now := time.Now().Unix()
	txBob := buildTx(dagA, bob.address, now)
	txCarol := buildTx(dagB, carol.address, now+1)

	if err := dagA.SubmitTx(txBob); err != nil {
		t.Fatalf("dagA SubmitTx(txBob) error = %v", err)
	}
	if err := dagB.SubmitTx(txCarol); err != nil {
		t.Fatalf("dagB SubmitTx(txCarol) error = %v", err)
	}

	if err := dagA.SubmitTx(cloneTransaction(txCarol)); err != nil {
		t.Fatalf("dagA import txCarol error = %v", err)
	}
	if err := dagB.SubmitTx(cloneTransaction(txBob)); err != nil {
		t.Fatalf("dagB import txBob error = %v", err)
	}

	if dagA.GetBalance(bob.address) != dagB.GetBalance(bob.address) {
		t.Fatalf("bob balance mismatch: dagA=%d dagB=%d", dagA.GetBalance(bob.address), dagB.GetBalance(bob.address))
	}
	if dagA.GetBalance(carol.address) != dagB.GetBalance(carol.address) {
		t.Fatalf("carol balance mismatch: dagA=%d dagB=%d", dagA.GetBalance(carol.address), dagB.GetBalance(carol.address))
	}
	if dagA.GetBalance(bob.address)+dagA.GetBalance(carol.address) != TotalSupply {
		t.Fatalf("effective supply = %d, want %d", dagA.GetBalance(bob.address)+dagA.GetBalance(carol.address), TotalSupply)
	}
}

func TestDAGSubmitTxRejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	wallet2 := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	genesisTxID := dag.genesis
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}

	tx := &Transaction{
		Parents: []string{genesisTxID, genesisTxID},
		Inputs:  []TxInput{{TxID: genesisTxID, Index: 0}},
		Outputs: []TxOutput{
			{Address: wallet2.address, Value: TotalSupply},
		},
		Timestamp: time.Now().Unix(),
	}
	wallet.signInput(t, tx, 0, genesisUTXO)
	// Tamper with the signature.
	tx.Inputs[0].Witness.Threshold.Signatures[0] = "deadbeef"
	mineTxPow(t, dag, tx)

	if err := dag.SubmitTx(tx); err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
}

func TestDAGConfirmation(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	// Low confirmation threshold so we need fewer txs.
	dag, err := NewDAG(Options{
		MinPowBits:            1,
		GenesisAddress:        wallet.address,
		ConfirmationThreshold: 5,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}

	genesisTxID := dag.genesis
	if dag.IsConfirmed(genesisTxID) {
		t.Fatal("genesis should not be confirmed yet (weight = 1, threshold = 5)")
	}

	// Submit enough txs to confirm genesis.
	prevID := genesisTxID
	currentAddr := wallet.address
	remaining := TotalSupply
	for i := 0; i < 5; i++ {
		utxos := dag.GetUTXOs(currentAddr)
		if len(utxos) == 0 {
			t.Fatalf("no UTXOs for wallet at step %d", i)
		}
		u := utxos[0]

		tx := &Transaction{
			Parents: []string{prevID, prevID},
			Inputs:  []TxInput{{TxID: u.TxID, Index: u.Index}},
			Outputs: []TxOutput{
				{Address: wallet.address, Value: remaining},
			},
			Timestamp: time.Now().Unix(),
		}
		wallet.signInput(t, tx, 0, u)
		mineTxPow(t, dag, tx)
		if err := dag.SubmitTx(tx); err != nil {
			t.Fatalf("SubmitTx step %d error = %v", i, err)
		}
		prevID = tx.ID
		currentAddr = wallet.address
	}

	if !dag.IsConfirmed(genesisTxID) {
		t.Errorf("genesis should be confirmed after 5 child txs (weight = %d, threshold = 5)", dag.TxWeight(genesisTxID))
	}
}

func TestDAGTips(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	genesisTxID := dag.genesis

	// Initially the genesis is the only tip.
	tips := dag.Tips()
	if len(tips) != 1 {
		t.Fatalf("expected 1 tip, got %d", len(tips))
	}

	// Build two independent transactions with same parent → two tips.
	halfValue := TotalSupply / 2

	buildTx := func(val int64, utxo *UTXO) *Transaction {
		tx := &Transaction{
			Parents:   []string{genesisTxID, genesisTxID},
			Inputs:    []TxInput{{TxID: utxo.TxID, Index: utxo.Index}},
			Outputs:   []TxOutput{{Address: wallet.address, Value: val}},
			Timestamp: time.Now().Unix(),
		}
		wallet.signInput(t, tx, 0, utxo)
		mineTxPow(t, dag, tx)
		return tx
	}

	genesisUTXO := dag.GetUTXOs(wallet.address)[0]

	// First tx: spend genesis UTXO, send half to wallet.
	tx1 := &Transaction{
		Parents: []string{genesisTxID, genesisTxID},
		Inputs:  []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs: []TxOutput{
			{Address: wallet.address, Value: halfValue},
			{Address: wallet.address, Value: TotalSupply - halfValue},
		},
		Timestamp: time.Now().Unix(),
	}
	wallet.signInput(t, tx1, 0, genesisUTXO)
	mineTxPow(t, dag, tx1)
	if err := dag.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx tx1 error = %v", err)
	}

	// Now there's 1 tip: tx1. Build tx2 using tx1's first output.
	utxo2 := dag.GetUTXOs(wallet.address)[0]
	tx2 := buildTx(utxo2.Value, utxo2)
	_ = tx2
	// Just verify we have 1 tip after tx1.
	if tips := dag.Tips(); len(tips) != 1 {
		t.Errorf("expected 1 tip after tx1, got %d", len(tips))
	}
}

func TestDAGPersist(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dir := t.TempDir()

	dag, err := NewDAG(Options{
		DataDir:        dir,
		MinPowBits:     1,
		GenesisAddress: wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}

	genesisTxID := dag.genesis
	genesisUTXO := dag.GetUTXOs(wallet.address)[0]

	tx := &Transaction{
		Parents:   []string{genesisTxID, genesisTxID},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: wallet.address, Value: TotalSupply}},
		Timestamp: time.Now().Unix(),
	}
	wallet.signInput(t, tx, 0, genesisUTXO)
	mineTxPow(t, dag, tx)
	if err := dag.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx() error = %v", err)
	}
	txID := tx.ID
	genesisWeight := dag.TxWeight(genesisTxID)
	txWeight := dag.TxWeight(txID)

	dag.Close()

	// Reopen and verify state was persisted.
	dag2, err := NewDAG(Options{
		DataDir:        dir,
		MinPowBits:     1,
		GenesisAddress: wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG (reload) error = %v", err)
	}
	defer dag2.Close()

	if dag2.Size() != 2 {
		t.Errorf("reloaded Size() = %d, want 2", dag2.Size())
	}
	if dag2.GetTransaction(txID) == nil {
		t.Errorf("reloaded tx %s not found", txID)
	}
	if got := dag2.GetBalance(wallet.address); got != TotalSupply {
		t.Errorf("reloaded balance = %d, want %d", got, TotalSupply)
	}
	if got := dag2.TxWeight(genesisTxID); got != genesisWeight {
		t.Errorf("reloaded genesis weight = %d, want %d", got, genesisWeight)
	}
	if got := dag2.TxWeight(txID); got != txWeight {
		t.Errorf("reloaded tx weight = %d, want %d", got, txWeight)
	}
}

func TestDAGSubmitTxDoesNotMutateStateOnPersistFailure(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	wallet2 := newTestWallet(t)
	dag, err := NewDAG(Options{
		DataDir:        t.TempDir(),
		MinPowBits:     1,
		GenesisAddress: wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}

	genesisTxID := dag.genesis
	genesisUTXO := dag.GetUTXOs(wallet.address)[0]
	tx := &Transaction{
		Parents: []string{genesisTxID, genesisTxID},
		Inputs:  []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs: []TxOutput{
			{Address: wallet2.address, Value: 1},
			{Address: wallet.address, Value: TotalSupply - 1},
		},
		Timestamp: time.Now().Unix(),
	}
	wallet.signInput(t, tx, 0, genesisUTXO)
	mineTxPow(t, dag, tx)

	if err := dag.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := dag.SubmitTx(tx); !errors.Is(err, ErrDAGClosed) {
		t.Fatalf("SubmitTx() after close error = %v, want %v", err, ErrDAGClosed)
	}

	if dag.Size() != 1 {
		t.Fatalf("Size() after failed persist = %d, want 1", dag.Size())
	}
	if dag.GetTransaction(tx.ID) != nil {
		t.Fatalf("failed tx %s unexpectedly present in DAG", tx.ID)
	}
	if got := dag.GetBalance(wallet.address); got != TotalSupply {
		t.Fatalf("wallet balance after failed persist = %d, want %d", got, TotalSupply)
	}
	if got := dag.GetBalance(wallet2.address); got != 0 {
		t.Fatalf("receiver balance after failed persist = %d, want 0", got)
	}
	if got := dag.TxWeight(genesisTxID); got != 1 {
		t.Fatalf("genesis weight after failed persist = %d, want 1", got)
	}
	if tips := dag.Tips(); len(tips) != 1 || tips[0] != genesisTxID {
		t.Fatalf("tips after failed persist = %v, want [%s]", tips, genesisTxID)
	}
}

func TestDAGCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dag := testNewDAG(t, &wallet)
	if err := dag.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := dag.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestDAGCloseConcurrent(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dag := testNewDAG(t, &wallet)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- dag.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Close() error = %v", err)
		}
	}
}

func TestDAGSelectTips(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	dag := testNewDAG(t, &wallet)

	// With only genesis, both tips should be genesis.
	p1, p2 := dag.SelectTips()
	if p1 == "" || p2 == "" {
		t.Fatal("SelectTips() returned empty tip ID")
	}
	if p1 != dag.genesis || p2 != dag.genesis {
		t.Errorf("SelectTips() with 1 tip: got (%s, %s), want both genesis", p1, p2)
	}
}

// ---- UTXO maturity tests ----

// TestUTXOMaturityRejected verifies that spending a UTXO before
// MinUTXOMaturitySeconds have elapsed is rejected.
func TestUTXOMaturityRejected(t *testing.T) {
	t.Parallel()

	alice := newTestWallet(t)
	bob := newTestWallet(t)
	dag := testNewDAG(t, &alice)

	now := time.Now().Unix()

	// tx1: spend the genesis UTXO (always mature — timestamp 1996) and create
	// a fresh UTXO for alice at now-100. Matures at now+500; no valid spending
	// tx timestamp can reach that (max future skew = 300s).
	genesisUTXO := dag.GetUTXOs(alice.address)[0]
	tx1 := &Transaction{
		Parents:   []string{dag.genesis, dag.genesis},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: alice.address, Value: TotalSupply}},
		Timestamp: now - 100, // UTXO CreatedAt=now-100, matures at now+500
	}
	alice.signInput(t, tx1, 0, genesisUTXO)
	mineTxPow(t, dag, tx1)
	if err := dag.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx(tx1) error = %v", err)
	}

	// tx2: Timestamp=now < (now-100)+600=now+500 → rejected by maturity rule.
	freshUTXO := dag.GetUTXOs(alice.address)[0]
	tx2 := &Transaction{
		Parents:   []string{tx1.ID, tx1.ID},
		Inputs:    []TxInput{{TxID: freshUTXO.TxID, Index: freshUTXO.Index}},
		Outputs:   []TxOutput{{Address: bob.address, Value: TotalSupply}},
		Timestamp: now,
	}
	alice.signInput(t, tx2, 0, freshUTXO)
	mineTxPow(t, dag, tx2)

	if err := dag.SubmitTx(tx2); err == nil {
		t.Fatal("expected maturity rejection, got nil")
	}
}

// TestUTXOMaturityAccepted verifies that spending a UTXO after
// MinUTXOMaturitySeconds have elapsed is accepted.
func TestUTXOMaturityAccepted(t *testing.T) {
	t.Parallel()

	alice := newTestWallet(t)
	bob := newTestWallet(t)
	dag := testNewDAG(t, &alice)

	now := time.Now().Unix()

	// tx1: create a UTXO 700 seconds ago (matures at now-100, already past).
	genesisUTXO := dag.GetUTXOs(alice.address)[0]
	tx1 := &Transaction{
		Parents:   []string{dag.genesis, dag.genesis},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: alice.address, Value: TotalSupply}},
		Timestamp: now - 700, // UTXO CreatedAt=now-700, matures at now-100
	}
	alice.signInput(t, tx1, 0, genesisUTXO)
	mineTxPow(t, dag, tx1)
	if err := dag.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx(tx1) error = %v", err)
	}

	// tx2: Timestamp=now >= (now-700)+600=now-100 → accepted.
	matureUTXO := dag.GetUTXOs(alice.address)[0]
	tx2 := &Transaction{
		Parents:   []string{tx1.ID, tx1.ID},
		Inputs:    []TxInput{{TxID: matureUTXO.TxID, Index: matureUTXO.Index}},
		Outputs:   []TxOutput{{Address: bob.address, Value: TotalSupply}},
		Timestamp: now,
	}
	alice.signInput(t, tx2, 0, matureUTXO)
	mineTxPow(t, dag, tx2)

	if err := dag.SubmitTx(tx2); err != nil {
		t.Fatalf("mature UTXO spend should succeed, got: %v", err)
	}
	if got := dag.GetBalance(bob.address); got != TotalSupply {
		t.Errorf("bob balance = %d, want %d", got, TotalSupply)
	}
}

// TestGenesisUTXOAlwaysMature verifies that the genesis output (timestamp 1996)
// satisfies the maturity rule for any current spending tx.
func TestGenesisUTXOAlwaysMature(t *testing.T) {
	t.Parallel()

	alice := newTestWallet(t)
	bob := newTestWallet(t)
	dag := testNewDAG(t, &alice)

	// GenesisTimestamp = 841353000 (Sep 1996). now >> 841353000+600.
	genesisUTXO := dag.GetUTXOs(alice.address)[0]
	if genesisUTXO.CreatedAt != GenesisTimestamp {
		t.Fatalf("genesis UTXO CreatedAt = %d, want GenesisTimestamp %d",
			genesisUTXO.CreatedAt, GenesisTimestamp)
	}

	tx := &Transaction{
		Parents:   []string{dag.genesis, dag.genesis},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: bob.address, Value: TotalSupply}},
		Timestamp: time.Now().Unix(),
	}
	alice.signInput(t, tx, 0, genesisUTXO)
	mineTxPow(t, dag, tx)

	if err := dag.SubmitTx(tx); err != nil {
		t.Fatalf("genesis spend should always be mature, got: %v", err)
	}
}

// TestPingPongNoMaturityGain verifies that bouncing coins between addresses
// does not shorten the maturity window. Each new UTXO gets CreatedAt from its
// own creating tx — hopping A→B resets the maturity clock to now.
func TestPingPongNoMaturityGain(t *testing.T) {
	t.Parallel()

	alice := newTestWallet(t)
	bob := newTestWallet(t)
	carol := newTestWallet(t)
	dag := testNewDAG(t, &alice)

	now := time.Now().Unix()
	T0 := now - 800 // alice's UTXO created; matures at T0+600=now-200

	genesisUTXO := dag.GetUTXOs(alice.address)[0]
	tx1 := &Transaction{
		Parents:   []string{dag.genesis, dag.genesis},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: alice.address, Value: TotalSupply}},
		Timestamp: T0,
	}
	alice.signInput(t, tx1, 0, genesisUTXO)
	mineTxPow(t, dag, tx1)
	if err := dag.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx(tx1) error = %v", err)
	}

	// T1=T0+601=now-199: alice's UTXO is mature; alice pings to bob.
	// Bob's new UTXO CreatedAt=T1=now-199; matures at now+401.
	T1 := T0 + 601
	aliceUTXO := dag.GetUTXOs(alice.address)[0]
	tx2 := &Transaction{
		Parents:   []string{tx1.ID, tx1.ID},
		Inputs:    []TxInput{{TxID: aliceUTXO.TxID, Index: aliceUTXO.Index}},
		Outputs:   []TxOutput{{Address: bob.address, Value: TotalSupply}},
		Timestamp: T1,
	}
	alice.signInput(t, tx2, 0, aliceUTXO)
	mineTxPow(t, dag, tx2)
	if err := dag.SubmitTx(tx2); err != nil {
		t.Fatalf("SubmitTx(tx2 alice→bob) error = %v", err)
	}

	// Bob's UTXO must have a fresh CreatedAt=T1, not alice's older T0.
	bobUTXO := dag.GetUTXOs(bob.address)[0]
	if bobUTXO.CreatedAt != T1 {
		t.Fatalf("bob UTXO CreatedAt = %d, want T1=%d (each hop resets the clock)",
			bobUTXO.CreatedAt, T1)
	}

	// T2=now: bob immediately pongs to carol. now < T1+600=now+401 → rejected.
	tx3 := &Transaction{
		Parents:   []string{tx2.ID, tx2.ID},
		Inputs:    []TxInput{{TxID: bobUTXO.TxID, Index: bobUTXO.Index}},
		Outputs:   []TxOutput{{Address: carol.address, Value: TotalSupply}},
		Timestamp: now,
	}
	bob.signInput(t, tx3, 0, bobUTXO)
	mineTxPow(t, dag, tx3)

	if err := dag.SubmitTx(tx3); err == nil {
		t.Fatal("ping-pong must not accelerate maturity: expected rejection, got nil")
	}
}

// TestFutureTimestampAttack verifies that stamping a UTXO with the maximum
// allowed future timestamp does not allow immediate spending. The spending tx
// is bound by the same MaxFutureSkewSeconds cap, so maturity still applies.
func TestFutureTimestampAttack(t *testing.T) {
	t.Parallel()

	alice := newTestWallet(t)
	bob := newTestWallet(t)
	dag := testNewDAG(t, &alice)

	now := time.Now().Unix()
	maxFuture := now + MaxFutureSkewSeconds // furthest timestamp the protocol allows

	// Create a UTXO with the maximum future timestamp.
	// CreatedAt=maxFuture; matures at maxFuture+MinUTXOMaturitySeconds.
	genesisUTXO := dag.GetUTXOs(alice.address)[0]
	tx1 := &Transaction{
		Parents:   []string{dag.genesis, dag.genesis},
		Inputs:    []TxInput{{TxID: genesisUTXO.TxID, Index: genesisUTXO.Index}},
		Outputs:   []TxOutput{{Address: alice.address, Value: TotalSupply}},
		Timestamp: maxFuture,
	}
	alice.signInput(t, tx1, 0, genesisUTXO)
	mineTxPow(t, dag, tx1)
	if err := dag.SubmitTx(tx1); err != nil {
		t.Fatalf("SubmitTx(tx1 maxFuture) error = %v", err)
	}

	attackUTXO := dag.GetUTXOs(alice.address)[0]
	if attackUTXO.CreatedAt != maxFuture {
		t.Fatalf("UTXO CreatedAt = %d, want maxFuture=%d", attackUTXO.CreatedAt, maxFuture)
	}

	// Best the attacker can do: spending tx also at maxFuture.
	// maxFuture < maxFuture+600 → maturity not met → rejected.
	tx2 := &Transaction{
		Parents:   []string{tx1.ID, tx1.ID},
		Inputs:    []TxInput{{TxID: attackUTXO.TxID, Index: attackUTXO.Index}},
		Outputs:   []TxOutput{{Address: bob.address, Value: TotalSupply}},
		Timestamp: maxFuture,
	}
	alice.signInput(t, tx2, 0, attackUTXO)
	mineTxPow(t, dag, tx2)

	if err := dag.SubmitTx(tx2); err == nil {
		t.Fatal("future-timestamp attack must be blocked by maturity: expected rejection, got nil")
	}
}
