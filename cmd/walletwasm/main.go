//go:build js && wasm

package main

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
	"syscall/js"

	"besoeasy/sikka/internal/wallet"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/sha3"
)

var wasmFuncs []js.Func

const (
	defaultMnemonicEntropyBits = 256
)

func main() {
	cryptoAPI := js.Global().Get("Object").New()
	cryptoAPI.Set("generateKeyHex", registerFunc(generateKeyHex))
	cryptoAPI.Set("generateMnemonic", registerFunc(generateMnemonic))
	cryptoAPI.Set("deriveKeyPairFromSeedHex", registerFunc(deriveKeyPairFromSeedHex))
	cryptoAPI.Set("deriveKeyPairFromMnemonic", registerFunc(deriveKeyPairFromMnemonic))
	cryptoAPI.Set("derivePathKeyPairFromSeedHex", registerFunc(derivePathKeyPairFromSeedHex))
	cryptoAPI.Set("derivePublicKeyHex", registerFunc(derivePublicKeyHex))
	cryptoAPI.Set("sha3Hex", registerFunc(sha3Hex))
	cryptoAPI.Set("mineTxPowNonceHex", registerFunc(mineTxPowNonceHex))
	cryptoAPI.Set("signHex", registerFunc(signHex))
	js.Global().Set("sikkaWalletCrypto", cryptoAPI)
	select {}
}

func registerFunc(fn func(js.Value, []js.Value) any) js.Func {
	wrapped := js.FuncOf(fn)
	wasmFuncs = append(wasmFuncs, wrapped)
	return wrapped
}

func generateKeyHex(js.Value, []js.Value) any {
	pk, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return errorResult(err)
	}
	material, err := wallet.KeyMaterialFromKeyPair(pk, sk)
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{
		"privateKeyHex": material.PrivateKeyHex,
		"publicKeyHex":  material.PublicKeyHex,
		"seedHex":       material.SeedHex,
		"address":       material.Address,
	})
}

func generateMnemonic(_ js.Value, args []js.Value) any {
	entropyBits := defaultMnemonicEntropyBits
	if len(args) > 0 {
		candidate := args[0].Int()
		if candidate != 0 {
			entropyBits = candidate
		}
	}
	mnemonic, err := wallet.GenerateMnemonic(entropyBits)
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{"mnemonic": mnemonic})
}

func deriveKeyPairFromSeedHex(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return errorResult(fmt.Errorf("seed hex is required"))
	}
	seed, err := wallet.SeedFromHex(args[0].String())
	if err != nil {
		return errorResult(err)
	}
	return keyPairResult(seed)
}

func deriveKeyPairFromMnemonic(_ js.Value, args []js.Value) any {
	if len(args) < 1 || len(args) > 2 {
		return errorResult(fmt.Errorf("mnemonic and optional passphrase are required"))
	}
	passphrase := ""
	if len(args) == 2 {
		passphrase = args[1].String()
	}
	seed, err := wallet.SeedFromMnemonic(args[0].String(), passphrase)
	if err != nil {
		return errorResult(err)
	}
	return keyPairResult(seed)
}

func derivePathKeyPairFromSeedHex(_ js.Value, args []js.Value) any {
	if len(args) != 4 {
		return errorResult(fmt.Errorf("seed hex, account, branch, and index are required"))
	}
	seed, err := wallet.SeedFromHex(args[0].String())
	if err != nil {
		return errorResult(err)
	}
	account, err := parseUint32Arg(args[1], "account")
	if err != nil {
		return errorResult(err)
	}
	branch, err := parseUint32Arg(args[2], "branch")
	if err != nil {
		return errorResult(err)
	}
	index, err := parseUint32Arg(args[3], "index")
	if err != nil {
		return errorResult(err)
	}
	material, err := wallet.KeyMaterialFromPath(seed, account, branch, index)
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{
		"privateKeyHex": material.PrivateKeyHex,
		"publicKeyHex":  material.PublicKeyHex,
		"seedHex":       material.SeedHex,
		"address":       material.Address,
		"account":       account,
		"branch":        branch,
		"index":         index,
	})
}

func derivePublicKeyHex(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return errorResult(fmt.Errorf("private key hex is required"))
	}
	sk, err := decodePrivateKeyHex(args[0].String())
	if err != nil {
		return errorResult(err)
	}
	pk, ok := sk.Public().(*mldsa87.PublicKey)
	if !ok {
		return errorResult(fmt.Errorf("unexpected public key type"))
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return errorResult(err)
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{
		"privateKeyHex": strings.ToLower(hex.EncodeToString(skBytes)),
		"publicKeyHex":  strings.ToLower(hex.EncodeToString(pkBytes)),
	})
}

func signHex(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return errorResult(fmt.Errorf("private key hex and payload hex are required"))
	}
	sk, err := decodePrivateKeyHex(args[0].String())
	if err != nil {
		return errorResult(err)
	}
	payloadHex := strings.TrimSpace(args[1].String())
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		return errorResult(fmt.Errorf("decode payload: %w", err))
	}
	sig, err := sk.Sign(nil, payload, crypto.Hash(0))
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{
		"signatureHex": strings.ToLower(hex.EncodeToString(sig)),
	})
}

func sha3Hex(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return errorResult(fmt.Errorf("payload hex is required"))
	}
	payload, err := decodeHexArg(args[0].String(), "payload")
	if err != nil {
		return errorResult(err)
	}
	digest := sha3.Sum256(payload)
	return js.ValueOf(map[string]any{
		"digestHex": strings.ToLower(hex.EncodeToString(digest[:])),
	})
}

func mineTxPowNonceHex(_ js.Value, args []js.Value) any {
	if len(args) != 4 {
		return errorResult(fmt.Errorf("mineTxPowNonceHex requires (txIDHex, parent0Hex, parent1Hex, requiredBits)"))
	}
	txIDHex := args[0].String()
	p0Hex := args[1].String()
	p1Hex := args[2].String()
	bitsVal := args[3]

	txID, err := decodeHexArg(txIDHex, "txID")
	if err != nil {
		return errorResult(err)
	}
	if len(txID) != 32 {
		return errorResult(fmt.Errorf("txID must be 32 bytes, got %d", len(txID)))
	}
	requiredBits := bitsVal.Int()
	if requiredBits < 0 {
		return errorResult(fmt.Errorf("required bits must be a non-negative integer"))
	}

	var buf [104]byte
	copy(buf[:32], txID)

	// Parent PoW hashes (tips commitment). Empty strings are treated as zeros
	// (for genesis or special cases). Must match txPowHash layout in internal/chain/crypto.go.
	p0Hex = strings.TrimSpace(p0Hex)
	if p0Hex != "" {
		if len(p0Hex) != 64 {
			return errorResult(fmt.Errorf("parent0 pow hash must be 64 hex chars, got %d", len(p0Hex)))
		}
		b, err := hex.DecodeString(p0Hex)
		if err != nil || len(b) != 32 {
			return errorResult(fmt.Errorf("parent0 pow hash invalid: %v", err))
		}
		copy(buf[32:64], b)
	}
	p1Hex = strings.TrimSpace(p1Hex)
	if p1Hex != "" {
		if len(p1Hex) != 64 {
			return errorResult(fmt.Errorf("parent1 pow hash must be 64 hex chars, got %d", len(p1Hex)))
		}
		b, err := hex.DecodeString(p1Hex)
		if err != nil || len(b) != 32 {
			return errorResult(fmt.Errorf("parent1 pow hash invalid: %v", err))
		}
		copy(buf[64:96], b)
	}

	for nonce := uint64(0); ; nonce++ {
		binary.BigEndian.PutUint64(buf[96:], nonce)
		hash := sha3.Sum256(buf[:])
		powBits := leadingZeroBits(hash[:])
		if powBits >= requiredBits {
			return js.ValueOf(map[string]any{
				"nonce":   float64(nonce),
				"powBits": powBits,
			})
		}
	}
}

func decodeHexArg(raw string, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
}

func leadingZeroBits(b []byte) int {
	count := 0
	for _, byt := range b {
		if byt == 0 {
			count += 8
			continue
		}
		return count + bits.LeadingZeros8(byt)
	}
	return count
}

func decodePrivateKeyHex(raw string) (*mldsa87.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	var sk mldsa87.PrivateKey
	if err := sk.UnmarshalBinary(keyBytes); err != nil {
		return nil, err
	}
	return &sk, nil
}

func parseUint32Arg(value js.Value, name string) (uint32, error) {
	v := value.Int()
	if v < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return uint32(v), nil
}

func keyPairResult(seed *[mldsa87.SeedSize]byte) any {
	material, err := wallet.KeyMaterialFromSeed(seed)
	if err != nil {
		return errorResult(err)
	}
	return js.ValueOf(map[string]any{
		"privateKeyHex": material.PrivateKeyHex,
		"publicKeyHex":  material.PublicKeyHex,
		"seedHex":       material.SeedHex,
		"address":       material.Address,
	})
}

func errorResult(err error) any {
	return js.ValueOf(map[string]any{"error": err.Error()})
}
