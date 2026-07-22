package chain

import (
	"testing"
)

func TestLRUCacheBasic(t *testing.T) {
	cache := newLRUCache(3)

	tx1 := &Transaction{ID: "tx1"}
	tx2 := &Transaction{ID: "tx2"}
	tx3 := &Transaction{ID: "tx3"}
	tx4 := &Transaction{ID: "tx4"}

	cache.Put(tx1.ID, tx1)
	cache.Put(tx2.ID, tx2)
	cache.Put(tx3.ID, tx3)

	if cache.Len() != 3 {
		t.Fatalf("expected cache len 3, got %d", cache.Len())
	}

	// Access tx1 so it becomes MRU (tx2 becomes LRU)
	if val, ok := cache.Get("tx1"); !ok || val.ID != "tx1" {
		t.Fatalf("failed to get tx1 from cache")
	}

	// Put tx4 -> should evict tx2 (the LRU item)
	cache.Put(tx4.ID, tx4)

	if _, ok := cache.Get("tx2"); ok {
		t.Fatalf("expected tx2 to be evicted from cache")
	}

	if _, ok := cache.Get("tx1"); !ok {
		t.Fatalf("expected tx1 to remain in cache")
	}
	if _, ok := cache.Get("tx3"); !ok {
		t.Fatalf("expected tx3 to remain in cache")
	}
	if _, ok := cache.Get("tx4"); !ok {
		t.Fatalf("expected tx4 to remain in cache")
	}
}

func TestLRUCacheRemove(t *testing.T) {
	cache := newLRUCache(5)
	tx1 := &Transaction{ID: "tx1"}
	cache.Put(tx1.ID, tx1)

	if cache.Len() != 1 {
		t.Fatalf("expected len 1, got %d", cache.Len())
	}

	cache.Remove("tx1")
	if cache.Len() != 0 {
		t.Fatalf("expected len 0 after remove, got %d", cache.Len())
	}
	if _, ok := cache.Get("tx1"); ok {
		t.Fatalf("expected tx1 to be removed")
	}
}
