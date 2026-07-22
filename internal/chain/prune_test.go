package chain

import (
	"testing"
	"time"
)

func testDAGWithPrune(t *testing.T, wallet testWallet) *DAG {
	t.Helper()
	dag, err := NewDAG(Options{
		MinPowBits:                1,
		ConfirmationThreshold:     2,
		ConflictPruneGraceSeconds: 1,
		GenesisAddress:            wallet.address,
	})
	if err != nil {
		t.Fatalf("NewDAG() error = %v", err)
	}
	return dag
}

func TestPruneLosingConflictAfterGrace(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	bob := newTestWallet(t)
	carol := newTestWallet(t)
	dag := testDAGWithPrune(t, wallet)

	genesisTxID := dag.genesis
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}
	stale := time.Now().Unix() - 3600

	buildSpend := func(d *DAG, recipient string, ts int64) *Transaction {
		tx := &Transaction{
			Parents:   []string{genesisTxID, genesisTxID},
			Inputs:    []TxInput{{TxID: genesisTxID, Index: 0}},
			Outputs:   []TxOutput{{Address: recipient, Value: TotalSupply}},
			Timestamp: ts,
		}
		wallet.signInput(t, tx, 0, genesisUTXO)
		mineTxPow(t, d, tx)
		return tx
	}

	txBob := buildSpend(dag, bob.address, stale)
	txCarol := buildSpend(dag, carol.address, stale+1)
	if err := dag.SubmitTx(txBob); err != nil {
		t.Fatalf("SubmitTx(txBob) error = %v", err)
	}
	if err := dag.SubmitTx(txCarol); err != nil {
		t.Fatalf("SubmitTx(txCarol) error = %v", err)
	}

	winner := txBob.ID
	if spendCandidateBetter(dag.weights, txCarol.ID, txBob.ID) {
		winner = txCarol.ID
	}
	loser := txBob.ID
	if winner == txBob.ID {
		loser = txCarol.ID
	}

	winnerWallet := bob
	if winner == txCarol.ID {
		winnerWallet = carol
	}
	lastTip := winner
	for i := 0; i < 4; i++ {
		utxos := dag.GetUTXOs(winnerWallet.address)
		if len(utxos) == 0 {
			t.Fatalf("winner %s has no spendable outputs before child %d", winner, i)
		}
		winnerUTXO := utxos[0]
		child := &Transaction{
			Parents:   []string{genesisTxID, lastTip},
			Inputs:    []TxInput{{TxID: winnerUTXO.TxID, Index: winnerUTXO.Index}},
			Outputs:   []TxOutput{{Address: winnerWallet.address, Value: winnerUTXO.Value}},
			Timestamp: winnerUTXO.CreatedAt + MinUTXOMaturitySeconds + int64(10+i),
		}
		winnerWallet.signInput(t, child, 0, winnerUTXO)
		mineTxPow(t, dag, child)
		if err := dag.SubmitTx(child); err != nil {
			t.Fatalf("SubmitTx(child %d) error = %v", i, err)
		}
		lastTip = child.ID
	}

	if dag.GetTransaction(loser) != nil {
		if pruned := dag.PruneLosingConflicts(); pruned == 0 {
			t.Fatalf("loser %s still present and PruneLosingConflicts() removed nothing", loser)
		}
	}
	if dag.GetTransaction(loser) != nil {
		t.Fatalf("loser %s still in DAG after prune", loser)
	}
	if dag.GetTransaction(winner) == nil {
		t.Fatalf("winner %s was pruned", winner)
	}
}

func TestPruneLosingConflictRespectsGraceWindow(t *testing.T) {
	t.Parallel()

	wallet := newTestWallet(t)
	bob := newTestWallet(t)
	carol := newTestWallet(t)
	dag := testDAGWithPrune(t, wallet)

	genesisTxID := dag.genesis
	genesisUTXO := &UTXO{
		TxID:    genesisTxID,
		Index:   0,
		Address: wallet.address,
		Value:   TotalSupply,
	}
	recent := time.Now().Unix()

	buildSpend := func(recipient string) *Transaction {
		tx := &Transaction{
			Parents:   []string{genesisTxID, genesisTxID},
			Inputs:    []TxInput{{TxID: genesisTxID, Index: 0}},
			Outputs:   []TxOutput{{Address: recipient, Value: TotalSupply}},
			Timestamp: recent,
		}
		wallet.signInput(t, tx, 0, genesisUTXO)
		mineTxPow(t, dag, tx)
		return tx
	}

	if err := dag.SubmitTx(buildSpend(bob.address)); err != nil {
		t.Fatalf("SubmitTx(txBob) error = %v", err)
	}
	if err := dag.SubmitTx(buildSpend(carol.address)); err != nil {
		t.Fatalf("SubmitTx(txCarol) error = %v", err)
	}
	if pruned := dag.PruneLosingConflicts(); pruned != 0 {
		t.Fatalf("PruneLosingConflicts() = %d, want 0 before grace window", pruned)
	}
	if dag.Size() != 3 {
		t.Fatalf("Size() = %d, want 3 before grace", dag.Size())
	}
}
