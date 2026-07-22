//go:build !js

package chain

import (
	"fmt"

	bbolt "go.etcd.io/bbolt"
)

// purgeUTXOFromDisk permanently deletes a UTXO from the bbolt database.
func purgeUTXOFromDisk(db *bbolt.DB, key string) error {
	return db.Batch(func(boltTx *bbolt.Tx) error {
		bkt := boltTx.Bucket([]byte(storageUTXOsBucket))
		if bkt == nil {
			return fmt.Errorf("utxos bucket missing")
		}
		return bkt.Delete([]byte(key))
	})
}

// RunUTXOSweep scans the UTXO set for outputs that have been canonically spent
// by a fully confirmed transaction. These UTXOs are cryptographically dead and
// can never be spent again. They are permanently removed from memory and disk
// to bound the ledger's space and memory complexity.
//
// Returns the number of UTXOs purged.
func (d *DAG) RunUTXOSweep() int {
	if err := d.beginOp(); err != nil {
		return 0
	}
	defer d.endOp()

	d.mu.RLock()
	var eligible []string
	for key := range d.utxos {
		claims := d.spendClaims[key]
		if len(claims) == 0 {
			continue
		}
		winner := canonicalSpenderLocked(d.weights, claims)
		if winner != "" && d.weights[winner] >= d.confirmationThreshold {
			eligible = append(eligible, key)
		}
	}
	d.mu.RUnlock()

	if len(eligible) == 0 {
		return 0
	}

	purged := 0
	for _, key := range eligible {
		// Remove from disk
		if d.db != nil {
			if err := purgeUTXOFromDisk(d.db, key); err != nil {
				continue
			}
		}

		// Remove from memory
		d.mu.Lock()
		if utxo, ok := d.utxos[key]; ok {
			d.removeUTXOFromAddrIndexLocked(utxo.Address, key)
			delete(d.utxos, key)
		}
		d.mu.Unlock()
		purged++
	}

	return purged
}
