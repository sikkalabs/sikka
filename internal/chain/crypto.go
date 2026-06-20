package chain

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/sha3"
)

const (
	AddressHRP           = "sikka"
	AddressVersion       = byte(1)
	bech32mConstant      = uint32(0x2bc830a3)
	bech32Charset        = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	WitnessTypeThreshold = "threshold"
	MaxThresholdKeys     = 16

	// signingDomain is prepended to every signing payload to prevent
	// cross-context signature replay.
	signingDomain = "sikka:v2:txinput"
)

var mldsaScheme = mldsa87.Scheme()

// NormalizeAddress normalizes a bech32m address to lowercase and validates its structure.
func NormalizeAddress(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return "", fmt.Errorf("address is required")
	}
	return normalizeModernAddress(trimmed)
}

// policyAddress derives a deterministic bech32m address from a threshold policy.
// publicKeys must already be sorted, lowercase hex-encoded ML-DSA-87 public keys.
func policyAddress(threshold int, publicKeys []string) (string, error) {
	if len(publicKeys) == 0 {
		return "", fmt.Errorf("policy requires at least one public key")
	}
	if threshold < 1 || threshold > len(publicKeys) {
		return "", fmt.Errorf("threshold must be between 1 and %d", len(publicKeys))
	}
	const scheme = "mldsa87"
	descriptor := fmt.Sprintf("%s:%d:[%s]", scheme, threshold, strings.Join(publicKeys, ","))
	payload := sha3.Sum256(append([]byte{AddressVersion}, []byte(descriptor)...))
	return encodeBech32mAddress(AddressHRP, AddressVersion, payload[:])
}

// multisigAddress derives a threshold policy address after canonicalizing keys.
// Kept for convenient use in tests and internal callers.
func multisigAddress(threshold int, publicKeys []string) (string, error) {
	canonical, err := canonicalizeThresholdPublicKeys(publicKeys)
	if err != nil {
		return "", err
	}
	return policyAddress(threshold, canonical)
}

// PolicyAddress is the exported form of policyAddress for external packages.
func PolicyAddress(threshold int, sortedPublicKeys []string) (string, error) {
	return policyAddress(threshold, sortedPublicKeys)
}

// SigningPayload returns the binary signing payload for a transaction input.
// Exported for use by wallets, tools, and tests in other packages.
func SigningPayload(tx *Transaction, inputIndex int, spentUTXO *UTXO) []byte {
	return signingPayloadBytes(tx, inputIndex, spentUTXO)
}

func normalizeModernAddress(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return "", fmt.Errorf("address is required")
	}
	if strings.ToLower(trimmed) != trimmed && strings.ToUpper(trimmed) != trimmed {
		return "", fmt.Errorf("address must use a single letter case")
	}
	normalized := strings.ToLower(trimmed)
	hr, version, program, err := decodeBech32mAddress(normalized)
	if err != nil {
		return "", err
	}
	if hr != AddressHRP {
		return "", fmt.Errorf("address hrp must be %s", AddressHRP)
	}
	if version != AddressVersion {
		return "", fmt.Errorf("address version must be %d", AddressVersion)
	}
	if len(program) != 32 {
		return "", fmt.Errorf("address program must be 32 bytes")
	}
	return normalized, nil
}

// verifyInputWitness verifies that tx.Inputs[inputIndex] is authorised to spend spentUTXO.
func verifyInputWitness(tx *Transaction, inputIndex int, spentUTXO *UTXO) error {
	if tx == nil {
		return fmt.Errorf("transaction is required")
	}
	if inputIndex < 0 || inputIndex >= len(tx.Inputs) {
		return fmt.Errorf("input index %d is out of range", inputIndex)
	}
	if spentUTXO == nil {
		return fmt.Errorf("spent utxo is required")
	}
	if tx.WitnessStripped {
		ageSeconds := time.Now().Unix() - tx.Timestamp
		if ageSeconds >= WitnessMinAgeSecs {
			// This transaction claims to be a compacted historical transaction.
			// We bypass signature verification. It will only become canonical if
			// the network has already built 1000+ weight on top of its specific TxID.
			return nil
		}
		return fmt.Errorf("input %d claims WitnessStripped but is too young (age %d sec < %d sec)", inputIndex, ageSeconds, WitnessMinAgeSecs)
	}

	witness := tx.Inputs[inputIndex].Witness
	if witness == nil {
		return fmt.Errorf("input %d witness is required", inputIndex)
	}
	payload := signingPayloadBytes(tx, inputIndex, spentUTXO)
	switch witness.Type {
	case WitnessTypeThreshold:
		return verifyThresholdWitness(payload, witness.Threshold, spentUTXO.Address)
	default:
		return fmt.Errorf("input %d witness type %q is unsupported", inputIndex, witness.Type)
	}
}

func verifyThresholdWitness(payload []byte, witness *ThresholdWitness, expectedAddress string) error {
	if witness == nil {
		return fmt.Errorf("threshold witness is required")
	}
	if len(witness.PublicKeys) == 0 {
		return fmt.Errorf("threshold witness requires at least one public key")
	}
	if len(witness.Signatures) != len(witness.PublicKeys) {
		return fmt.Errorf("threshold signatures length must equal public_keys length")
	}
	canonicalKeys, err := canonicalizeThresholdPublicKeys(witness.PublicKeys)
	if err != nil {
		return err
	}
	if !equalStringSlices(canonicalKeys, witness.PublicKeys) {
		return fmt.Errorf("threshold public_keys must be sorted and unique")
	}
	derivedAddress, err := policyAddress(witness.Threshold, canonicalKeys)
	if err != nil {
		return err
	}
	normalizedExpected, err := NormalizeAddress(expectedAddress)
	if err != nil {
		return err
	}
	if derivedAddress != normalizedExpected {
		return fmt.Errorf("threshold witness does not control input address")
	}
	validCount := 0
	for i, sigHex := range witness.Signatures {
		if sigHex == "" {
			continue
		}
		var verifyErr error
		verifyErr = verifyMLDSA87Signature(canonicalKeys[i], sigHex, payload)
		if verifyErr != nil {
			return fmt.Errorf("signature %d invalid: %w", i, verifyErr)
		}
		validCount++
	}
	if validCount < witness.Threshold {
		return fmt.Errorf("threshold witness has %d valid signatures, need %d", validCount, witness.Threshold)
	}
	return nil
}

// signingPayloadBytes builds the deterministic binary signing payload for
// tx.Inputs[inputIndex] spending spentUTXO.
//
// Layout (all multi-byte integers big-endian):
//
//	[16]  domain prefix "sikka:v2:txinput"
//	[32]  SHA3-256 of canonical tx body (txID)
//	[8]   input_index (uint64)
//	[32]  spent_txid bytes
//	[8]   spent_index (uint64)
//	[8]   spent_value (uint64)
//	[2]   spent_address length (uint16)
//	[N]   spent_address UTF-8 bytes
func signingPayloadBytes(tx *Transaction, inputIndex int, spentUTXO *UTXO) []byte {
	txIDBytes := computeTxIDRaw(tx)
	addrBytes := []byte(spentUTXO.Address)
	spentTxIDBytes := decodeHash32(spentUTXO.TxID)
	buf := make([]byte, 0, len(signingDomain)+32+8+32+8+8+2+len(addrBytes))
	buf = append(buf, []byte(signingDomain)...)
	buf = append(buf, txIDBytes[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(inputIndex))
	buf = append(buf, spentTxIDBytes...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(spentUTXO.Index))
	buf = binary.BigEndian.AppendUint64(buf, uint64(spentUTXO.Value))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(addrBytes)))
	buf = append(buf, addrBytes...)
	return buf
}

// computeTxID returns the hex-encoded SHA3-256 transaction ID.
// The ID covers parents, inputs (outpoints only), outputs, and timestamp.
// It intentionally excludes witness data, pow_nonce, and pow_bits.
func computeTxID(tx *Transaction) string {
	h := computeTxIDRaw(tx)
	return hex.EncodeToString(h[:])
}

// computeTxIDRaw computes the raw 32-byte SHA3-256 transaction ID.
//
// Binary layout (big-endian):
//
//	[1]  encoding version (0x02)
//	[4]  number of parents (uint32)
//	     for each parent:
//	         [32] parent tx ID bytes
//	[4]  number of inputs (uint32)
//	     for each input:
//	         [32] txid bytes
//	         [4]  index (uint32)
//	[4]  number of outputs (uint32)
//	     for each output:
//	         [2]  address length (uint16)
//	         [N]  address UTF-8 bytes
//	         [8]  value (uint64)
//	[8]  timestamp (uint64)
func computeTxIDRaw(tx *Transaction) [32]byte {
	var buf []byte
	buf = append(buf, 0x02)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Parents)))
	for _, parentID := range tx.Parents {
		buf = append(buf, decodeHash32(parentID)...)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		buf = append(buf, decodeHash32(in.TxID)...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(in.Index))
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		addrBytes := []byte(out.Address)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(addrBytes)))
		buf = append(buf, addrBytes...)
		buf = binary.BigEndian.AppendUint64(buf, uint64(out.Value))
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(tx.Timestamp))
	return sha3.Sum256(buf)
}

// txPowHash computes the SHA3-256 proof-of-work hash for a transaction.
// It hashes the stable txID, the parent PoW hashes (tips commitment), and the
// pow_nonce. Including the parent PoW hashes binds the PoW work to a specific
// DAG state, preventing selfish mining: if an attacker pre-mines against old
// tips the parent hashes won't match the current DAG, invalidating the work.
//
// Layout:
//
//	[32] txID bytes
//	[32] parent[0] PoW hash bytes (zeros if absent / genesis)
//	[32] parent[1] PoW hash bytes (zeros if absent / genesis)
//	[8]  pow_nonce (uint64 big-endian)
func txPowHash(tx *Transaction) ([32]byte, error) {
	txIDBytes := computeTxIDRaw(tx)

	// Decode parent PoW hashes. We always mix in exactly 2 × 32 bytes so the
	// hash input layout is fixed regardless of how many parents are present.
	// Genesis has no parents and no ParentPowHashes — we use 64 zero bytes.
	var p0, p1 [32]byte // zero-value = safe default for genesis
	if len(tx.ParentPowHashes) >= 1 {
		if len(tx.ParentPowHashes[0]) != 64 {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[0] must be 64 hex chars")
		}
		b, err := hex.DecodeString(tx.ParentPowHashes[0])
		if err != nil {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[0]: %w", err)
		}
		copy(p0[:], b)
	}
	if len(tx.ParentPowHashes) >= 2 {
		if len(tx.ParentPowHashes[1]) != 64 {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[1] must be 64 hex chars")
		}
		b, err := hex.DecodeString(tx.ParentPowHashes[1])
		if err != nil {
			return [32]byte{}, fmt.Errorf("parent_pow_hashes[1]: %w", err)
		}
		copy(p1[:], b)
	}

	var buf [32 + 32 + 32 + 8]byte // txID + p0 + p1 + nonce
	copy(buf[0:32], txIDBytes[:])
	copy(buf[32:64], p0[:])
	copy(buf[64:96], p1[:])
	binary.BigEndian.PutUint64(buf[96:], uint64(tx.PowNonce))
	return sha3.Sum256(buf[:]), nil
}

// verifyMLDSA87Signature verifies an ML-DSA-87 signature over payload.
func verifyMLDSA87Signature(pkHex string, sigHex string, payload []byte) error {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return fmt.Errorf("decode public_key: %w", err)
	}
	pk, err := mldsaScheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return fmt.Errorf("unmarshal public_key: %w", err)
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) != mldsaScheme.SignatureSize() {
		return fmt.Errorf("signature must be %d bytes, got %d", mldsaScheme.SignatureSize(), len(sigBytes))
	}
	if !mldsaScheme.Verify(pk, payload, sigBytes, nil) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// canonicalizeThresholdPublicKeys validates, normalizes, deduplicates, and sorts
// a list of ML-DSA-87 public key hex strings.
func canonicalizeThresholdPublicKeys(publicKeys []string) ([]string, error) {
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("threshold public_keys are required")
	}
	if len(publicKeys) > MaxThresholdKeys {
		return nil, fmt.Errorf("threshold cannot exceed %d public keys", MaxThresholdKeys)
	}
	canonical := make([]string, 0, len(publicKeys))
	seen := make(map[string]bool, len(publicKeys))
	for _, pkHex := range publicKeys {
		normalized, err := normalizePublicKeyHex(pkHex)
		if err != nil {
			return nil, err
		}
		if seen[normalized] {
			return nil, fmt.Errorf("threshold public_keys must be unique")
		}
		seen[normalized] = true
		canonical = append(canonical, normalized)
	}
	sort.Strings(canonical)
	return canonical, nil
}

// normalizePublicKeyHex validates and returns a lowercase hex ML-DSA-87 public key.
func normalizePublicKeyHex(pkHex string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(pkHex))
	if normalized == "" {
		return "", fmt.Errorf("public_key is required")
	}
	pkBytes, err := hex.DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("decode public_key: %w", err)
	}
	if len(pkBytes) != mldsaScheme.PublicKeySize() {
		return "", fmt.Errorf("public_key must be %d bytes (ML-DSA-87), got %d",
			mldsaScheme.PublicKeySize(), len(pkBytes))
	}
	return normalized, nil
}

// equalStringSlices reports whether two string slices are bytewise equal.
// It does NOT normalize either side: it is used in witness validation to
// enforce that the user submitted already-canonical (sorted, lowercase,
// trimmed, unique) public keys, which is required for deterministic policy
// address derivation.
func equalStringSlices(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// decodeHash32 hex-decodes a 32-byte hash string. It is a strict helper used
// by the txID / signing-payload encoders: every caller in this package is
// expected to have already verified the input is a 64-char hex string (see
// validateTxLocked). Empty / malformed input is a programmer error and
// triggers a panic rather than silently producing a 32-byte zero slice that
// would compute a deterministically wrong tx ID or signature payload.
func decodeHash32(hashHex string) []byte {
	if len(hashHex) != 64 {
		panic(fmt.Sprintf("decodeHash32: expected 64 hex chars, got %d (%q)", len(hashHex), hashHex))
	}
	b, err := hex.DecodeString(hashHex)
	if err != nil {
		panic(fmt.Sprintf("decodeHash32: invalid hex %q: %v", hashHex, err))
	}
	return b
}

// ---- bech32m encoder / decoder ----

func encodeBech32mAddress(hrp string, version byte, program []byte) (string, error) {
	if hrp == "" {
		return "", fmt.Errorf("address hrp is required")
	}
	if len(program) == 0 {
		return "", fmt.Errorf("address program is required")
	}
	converted, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]byte{version}, converted...)
	checksum := bech32CreateChecksum(hrp, data, bech32mConstant)
	combined := append(data, checksum...)
	var out strings.Builder
	out.Grow(len(hrp) + 1 + len(combined))
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, value := range combined {
		if int(value) >= len(bech32Charset) {
			return "", fmt.Errorf("invalid bech32 value %d", value)
		}
		out.WriteByte(bech32Charset[value])
	}
	return out.String(), nil
}

func decodeBech32mAddress(address string) (string, byte, []byte, error) {
	separator := strings.LastIndexByte(address, '1')
	if separator < 1 || separator+7 > len(address) {
		return "", 0, nil, fmt.Errorf("invalid bech32m address length")
	}
	hr := address[:separator]
	encoded := address[separator+1:]
	values := make([]byte, len(encoded))
	for i := range encoded {
		index := strings.IndexByte(bech32Charset, encoded[i])
		if index < 0 {
			return "", 0, nil, fmt.Errorf("invalid bech32m character %q", encoded[i])
		}
		values[i] = byte(index)
	}
	if !bech32VerifyChecksum(hr, values, bech32mConstant) {
		return "", 0, nil, fmt.Errorf("invalid bech32m checksum")
	}
	values = values[:len(values)-6]
	if len(values) == 0 {
		return "", 0, nil, fmt.Errorf("address payload is empty")
	}
	program, err := convertBits(values[1:], 5, 8, false)
	if err != nil {
		return "", 0, nil, err
	}
	return hr, values[0], program, nil
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := 0
	bits := uint(0)
	maxValue := (1 << toBits) - 1
	maxAcc := (1 << (fromBits + toBits - 1)) - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range for bit conversion")
		}
		acc = ((acc << fromBits) | int(value)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxValue))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxValue))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxValue) != 0 {
		return nil, fmt.Errorf("invalid padding in address payload")
	}
	return out, nil
}

func bech32CreateChecksum(hrp string, data []byte, constant uint32) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ constant
	checksum := make([]byte, 6)
	for i := range checksum {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return checksum
}

func bech32VerifyChecksum(hrp string, values []byte, constant uint32) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), values...)) == constant
}

func bech32HRPExpand(hrp string) []byte {
	values := make([]byte, 0, len(hrp)*2+1)
	for i := range hrp {
		values = append(values, hrp[i]>>5)
	}
	values = append(values, 0)
	for i := range hrp {
		values = append(values, hrp[i]&31)
	}
	return values
}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(value)
		if top&1 != 0 {
			chk ^= 0x3b6a57b2
		}
		if top&2 != 0 {
			chk ^= 0x26508e6d
		}
		if top&4 != 0 {
			chk ^= 0x1ea119fa
		}
		if top&8 != 0 {
			chk ^= 0x3d4233dd
		}
		if top&16 != 0 {
			chk ^= 0x2a1462b3
		}
	}
	return chk
}
