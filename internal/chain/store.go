//go:build !js

package chain

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	bbolt "go.etcd.io/bbolt"
)

const (
	storageFormatVersion = "2"

	storageMetaBucket    = "meta"
	storageTxsBucket     = "txs"
	storageWeightsBucket = "weights"
	storageUTXOsBucket   = "utxos"
	storageSpentBucket   = "spent"
	storageFormatKey     = "format"
)

// openStorage opens (or creates) a bbolt database at path.
// If readOnly is true the file is opened in read-only mode.
func openStorage(path string, readOnly bool) (*bbolt.DB, error) {
	opts := &bbolt.Options{ReadOnly: readOnly}
	db, err := bbolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, fmt.Errorf("open storage %s: %w", path, err)
	}
	return db, nil
}

// initBuckets creates all DAG buckets if they do not exist.
func initBuckets(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		buckets := []string{
			storageMetaBucket,
			storageTxsBucket,
			storageWeightsBucket,
			storageUTXOsBucket,
			storageSpentBucket,
		}
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		meta := tx.Bucket([]byte(storageMetaBucket))
		return meta.Put([]byte(storageFormatKey), []byte(storageFormatVersion))
	})
}

// persistTx writes a single transaction to the txs bucket.
func persistTx(db *bbolt.DB, tx *Transaction) error {
	payload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx %s: %w", tx.ID, err)
	}
	return db.Update(func(boltTx *bbolt.Tx) error {
		return boltTx.Bucket([]byte(storageTxsBucket)).Put([]byte(tx.ID), payload)
	})
}

// persistWeight writes the cumulative weight for a tx ID.
func persistWeight(db *bbolt.DB, txID string, weight int64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(weight))
	return db.Update(func(boltTx *bbolt.Tx) error {
		return boltTx.Bucket([]byte(storageWeightsBucket)).Put([]byte(txID), buf[:])
	})
}

// persistUTXO writes a UTXO to the utxos bucket.
func persistUTXO(db *bbolt.DB, key string, u *UTXO) error {
	payload, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("marshal utxo %s: %w", key, err)
	}
	return db.Update(func(boltTx *bbolt.Tx) error {
		return boltTx.Bucket([]byte(storageUTXOsBucket)).Put([]byte(key), payload)
	})
}

func decodeSpendClaimValue(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var claims []string
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	return claims
}

func persistSpendClaim(bkt *bbolt.Bucket, key string, spenderID string) error {
	existing := decodeSpendClaimValue(bkt.Get([]byte(key)))
	merged := appendSpendClaim(existing, spenderID)
	payload, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal spend claims %s: %w", key, err)
	}
	return bkt.Put([]byte(key), payload)
}

// persistAddTx atomically writes a new transaction, all affected weight
// updates, the spent inputs, and the new UTXOs in a single bbolt transaction.
// A crash before this call commits leaves the database unchanged; a crash
// after means the full entry is present.
//
// Uses db.Batch so that multiple concurrent SubmitTx calls coalesce into a
// single fsync (bbolt batches writes within MaxBatchDelay, default 10ms).
// The closure is idempotent (deterministic key/value Puts and Deletes), so
// bbolt is free to retry it if a batch participant fails.
func persistAddTx(db *bbolt.DB, tx *Transaction, weightUpdates map[string]int64, spentKeys []string, newUTXOs map[string]*UTXO) error {
	txPayload, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal tx %s: %w", tx.ID, err)
	}

	utxoPayloads := make(map[string][]byte, len(newUTXOs))
	for key, u := range newUTXOs {
		payload, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("marshal utxo %s: %w", key, err)
		}
		utxoPayloads[key] = payload
	}

	return db.Batch(func(boltTx *bbolt.Tx) error {
		txsBkt := boltTx.Bucket([]byte(storageTxsBucket))
		weightsBkt := boltTx.Bucket([]byte(storageWeightsBucket))
		utxosBkt := boltTx.Bucket([]byte(storageUTXOsBucket))
		spentBkt := boltTx.Bucket([]byte(storageSpentBucket))

		if err := txsBkt.Put([]byte(tx.ID), txPayload); err != nil {
			return fmt.Errorf("persist tx: %w", err)
		}
		for txID, weight := range weightUpdates {
			// Allocate a fresh buffer per Put: bbolt requires the value
			// slice to remain valid for the life of the transaction, so a
			// shared buffer would clobber earlier writes.
			wBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(wBuf, uint64(weight))
			if err := weightsBkt.Put([]byte(txID), wBuf); err != nil {
				return fmt.Errorf("persist weight %s: %w", txID, err)
			}
		}
		for _, key := range spentKeys {
			if err := persistSpendClaim(spentBkt, key, tx.ID); err != nil {
				return fmt.Errorf("record spend claim %s: %w", key, err)
			}
		}
		for key, payload := range utxoPayloads {
			if err := utxosBkt.Put([]byte(key), payload); err != nil {
				return fmt.Errorf("persist utxo %s: %w", key, err)
			}
		}
		return nil
	})
}

func persistAddTxs(db *bbolt.DB, txs []*Transaction, weightUpdates map[string]int64, spendClaims map[string][]string, newUTXOs map[string]*UTXO) error {
	txPayloads := make(map[string][]byte, len(txs))
	for _, tx := range txs {
		payload, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("marshal tx %s: %w", tx.ID, err)
		}
		txPayloads[tx.ID] = payload
	}

	utxoPayloads := make(map[string][]byte, len(newUTXOs))
	for key, u := range newUTXOs {
		payload, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("marshal utxo %s: %w", key, err)
		}
		utxoPayloads[key] = payload
	}

	return db.Batch(func(boltTx *bbolt.Tx) error {
		txsBkt := boltTx.Bucket([]byte(storageTxsBucket))
		weightsBkt := boltTx.Bucket([]byte(storageWeightsBucket))
		utxosBkt := boltTx.Bucket([]byte(storageUTXOsBucket))
		spentBkt := boltTx.Bucket([]byte(storageSpentBucket))

		for id, payload := range txPayloads {
			if err := txsBkt.Put([]byte(id), payload); err != nil {
				return fmt.Errorf("persist tx %s: %w", id, err)
			}
		}
		for txID, weight := range weightUpdates {
			wBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(wBuf, uint64(weight))
			if err := weightsBkt.Put([]byte(txID), wBuf); err != nil {
				return fmt.Errorf("persist weight %s: %w", txID, err)
			}
		}
		for key, claimants := range spendClaims {
			for _, spenderID := range claimants {
				if err := persistSpendClaim(spentBkt, key, spenderID); err != nil {
					return fmt.Errorf("record spend claim %s: %w", key, err)
				}
			}
		}
		for key, payload := range utxoPayloads {
			if err := utxosBkt.Put([]byte(key), payload); err != nil {
				return fmt.Errorf("persist utxo %s: %w", key, err)
			}
		}
		return nil
	})
}

// loadDAGState loads all persisted DAG state from db into the provided maps.
func loadDAGState(db *bbolt.DB) (
	txs map[string]*Transaction,
	weights map[string]int64,
	utxos map[string]*UTXO,
	spendClaims map[string][]string,
	err error,
) {
	txs = make(map[string]*Transaction)
	weights = make(map[string]int64)
	utxos = make(map[string]*UTXO)
	spendClaims = make(map[string][]string)

	err = db.View(func(boltTx *bbolt.Tx) error {
		// Validate storage format version. Versions newer than the current one
		// are rejected so that old software does not silently corrupt a newer
		// database.
		if b := boltTx.Bucket([]byte(storageMetaBucket)); b != nil {
			ver := string(b.Get([]byte(storageFormatKey)))
			if ver != "" && ver != storageFormatVersion {
				return fmt.Errorf(
					"unsupported storage format version %q (want %q): "+
						"delete the database file to reset",
					ver, storageFormatVersion,
				)
			}
		}
		// Load transactions.
		if b := boltTx.Bucket([]byte(storageTxsBucket)); b != nil {
			if e := b.ForEach(func(k, v []byte) error {
				var tx Transaction
				if e := json.Unmarshal(v, &tx); e != nil {
					return fmt.Errorf("unmarshal tx %s: %w", k, e)
				}
				txs[string(k)] = &tx
				return nil
			}); e != nil {
				return e
			}
		}
		// Load weights.
		if b := boltTx.Bucket([]byte(storageWeightsBucket)); b != nil {
			if e := b.ForEach(func(k, v []byte) error {
				if len(v) != 8 {
					return nil
				}
				weights[string(k)] = int64(binary.BigEndian.Uint64(v))
				return nil
			}); e != nil {
				return e
			}
		}
		// Load UTXOs.
		if b := boltTx.Bucket([]byte(storageUTXOsBucket)); b != nil {
			if e := b.ForEach(func(k, v []byte) error {
				var u UTXO
				if e := json.Unmarshal(v, &u); e != nil {
					return fmt.Errorf("unmarshal utxo %s: %w", k, e)
				}
				utxos[string(k)] = &u
				return nil
			}); e != nil {
				return e
			}
		}
		// Load spend-claim index.
		if b := boltTx.Bucket([]byte(storageSpentBucket)); b != nil {
			if e := b.ForEach(func(k, v []byte) error {
				spendClaims[string(k)] = decodeSpendClaimValue(v)
				return nil
			}); e != nil {
				return e
			}
		}
		return nil
	})
	return
}

// persistPruneLedger deletes pruned transactions and rewrites the utxo and
// spend-claim buckets from the post-prune in-memory ledger view.
func persistPruneLedger(db *bbolt.DB, prunedIDs []string, utxos map[string]*UTXO, spendClaims map[string][]string) error {
	if len(prunedIDs) == 0 {
		return nil
	}
	utxoPayloads := make(map[string][]byte, len(utxos))
	for key, u := range utxos {
		payload, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("marshal utxo %s: %w", key, err)
		}
		utxoPayloads[key] = payload
	}
	claimPayloads := make(map[string][]byte, len(spendClaims))
	for key, claims := range spendClaims {
		payload, err := json.Marshal(claims)
		if err != nil {
			return fmt.Errorf("marshal spend claims %s: %w", key, err)
		}
		claimPayloads[key] = payload
	}

	return db.Batch(func(boltTx *bbolt.Tx) error {
		txsBkt := boltTx.Bucket([]byte(storageTxsBucket))
		weightsBkt := boltTx.Bucket([]byte(storageWeightsBucket))
		utxosBkt := boltTx.Bucket([]byte(storageUTXOsBucket))
		spentBkt := boltTx.Bucket([]byte(storageSpentBucket))
		if txsBkt == nil || weightsBkt == nil || utxosBkt == nil || spentBkt == nil {
			return fmt.Errorf("storage buckets missing")
		}
		for _, id := range prunedIDs {
			if err := txsBkt.Delete([]byte(id)); err != nil {
				return fmt.Errorf("delete tx %s: %w", id, err)
			}
			if err := weightsBkt.Delete([]byte(id)); err != nil {
				return fmt.Errorf("delete weight %s: %w", id, err)
			}
		}
		if err := clearBucket(utxosBkt); err != nil {
			return err
		}
		if err := clearBucket(spentBkt); err != nil {
			return err
		}
		for key, payload := range utxoPayloads {
			if err := utxosBkt.Put([]byte(key), payload); err != nil {
				return fmt.Errorf("persist utxo %s: %w", key, err)
			}
		}
		for key, payload := range claimPayloads {
			if err := spentBkt.Put([]byte(key), payload); err != nil {
				return fmt.Errorf("persist spend claims %s: %w", key, err)
			}
		}
		return nil
	})
}

func clearBucket(bkt *bbolt.Bucket) error {
	var keys [][]byte
	if err := bkt.ForEach(func(k, _ []byte) error {
		keys = append(keys, append([]byte(nil), k...))
		return nil
	}); err != nil {
		return err
	}
	for _, key := range keys {
		if err := bkt.Delete(key); err != nil {
			return err
		}
	}
	return nil
}
