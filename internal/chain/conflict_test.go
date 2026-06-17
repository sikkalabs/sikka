package chain

import "testing"

func TestSpendCandidateBetter(t *testing.T) {
	t.Parallel()

	weights := map[string]int64{
		"a": 10,
		"b": 5,
		"c": 10,
		"d": 10,
	}

	if !spendCandidateBetter(weights, "a", "b") {
		t.Fatal("expected higher weight to win")
	}
	if spendCandidateBetter(weights, "b", "a") {
		t.Fatal("expected lower weight to lose")
	}
	if !spendCandidateBetter(weights, "c", "d") {
		t.Fatal("expected lower tx id to win equal-weight tie")
	}
	if spendCandidateBetter(weights, "d", "c") {
		t.Fatal("expected higher tx id to lose equal-weight tie")
	}
}
