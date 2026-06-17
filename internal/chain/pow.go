package chain

import "context"

// MineTxPoW iterates the PowNonce until the tx achieves at least minBits
// leading zero bits in its PoW hash. It sets tx.PowBits to the achieved bits.
//
// The context is checked every 1024 iterations so that excessive PoW
// requirements (e.g. due to misconfiguration or extreme congestion) can be
// cancelled rather than spinning forever.
func MineTxPoW(ctx context.Context, tx *Transaction, minBits int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for nonce := int64(0); ; nonce++ {
		if nonce&0x3ff == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		tx.PowNonce = nonce
		hash, err := txPowHash(tx)
		if err != nil {
			return err
		}
		bits := leadingZeroBits(hash[:])
		if bits >= minBits {
			tx.PowBits = bits
			return nil
		}
	}
}
