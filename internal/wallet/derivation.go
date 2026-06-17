package wallet

import (
	"besoeasy/sikka/internal/chain"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	WalletVersion          = 1
	MnemonicDerivationV1   = "bip39-hkdf-sha3-256-mldsa87-v1"
	HDMnemonicDerivationV1 = "bip39-hd-hkdf-sha3-256-mldsa87-v1"
	SeedDerivationV1       = "raw-seed-mldsa87-v1"
	RandomDerivationV1     = "random-mldsa87-v1"
	PrivateKeyImportV1     = "private-key-import-mldsa87-v1"
	defaultMnemonicInfo    = "sikka:mldsa87:bip39:v1"
	defaultHDInfo          = "sikka:mldsa87:hd:v1"
	ExternalChain          = uint32(0)
	InternalChain          = uint32(1)
)

type KeyMaterial struct {
	PrivateKeyHex string
	PublicKeyHex  string
	SeedHex       string
	Address       string
}

func NormalizeMnemonic(raw string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(raw))), " ")
}

func GenerateMnemonic(entropyBits int) (string, error) {
	if entropyBits == 0 {
		entropyBits = 256
	}
	if entropyBits < 128 || entropyBits > 256 || entropyBits%32 != 0 {
		return "", fmt.Errorf("mnemonic entropy must be 128, 160, 192, 224, or 256 bits")
	}
	entropy, err := bip39GenEntropy(entropyBits)
	if err != nil {
		return "", err
	}
	return bip39NewMnemonic(entropy)
}

func SeedFromHex(raw string) (*[mldsa87.SeedSize]byte, error) {
	seedBytes, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("decode seed: %w", err)
	}
	if len(seedBytes) != mldsa87.SeedSize {
		return nil, fmt.Errorf("ML-DSA-87 seed must be %d bytes (%d hex chars)", mldsa87.SeedSize, mldsa87.SeedSize*2)
	}
	var seed [mldsa87.SeedSize]byte
	copy(seed[:], seedBytes)
	return &seed, nil
}

func SeedFromMnemonic(rawMnemonic, passphrase string) (*[mldsa87.SeedSize]byte, error) {
	mnemonic := NormalizeMnemonic(rawMnemonic)
	if mnemonic == "" {
		return nil, fmt.Errorf("mnemonic is required")
	}
	if !bip39IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("mnemonic is invalid or not in the supported BIP-39 wordlist")
	}
	bip39Seed := bip39NewSeed(mnemonic, passphrase)
	reader := hkdf.New(sha3.New256, bip39Seed, nil, []byte(defaultMnemonicInfo))
	var seed [mldsa87.SeedSize]byte
	if _, err := io.ReadFull(reader, seed[:]); err != nil {
		return nil, fmt.Errorf("derive mnemonic seed: %w", err)
	}
	return &seed, nil
}

func KeyMaterialFromSeed(seed *[mldsa87.SeedSize]byte) (*KeyMaterial, error) {
	if seed == nil {
		return nil, fmt.Errorf("seed is required")
	}
	pk, sk := mldsa87.NewKeyFromSeed(seed)
	return KeyMaterialFromKeyPair(pk, sk)
}

func KeyMaterialFromMnemonic(rawMnemonic, passphrase string) (*KeyMaterial, error) {
	seed, err := SeedFromMnemonic(rawMnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	return KeyMaterialFromSeed(seed)
}

func DerivePathSeed(masterSeed *[mldsa87.SeedSize]byte, account, branch, index uint32) (*[mldsa87.SeedSize]byte, error) {
	if masterSeed == nil {
		return nil, fmt.Errorf("master seed is required")
	}
	info := make([]byte, len(defaultHDInfo)+12)
	copy(info, []byte(defaultHDInfo))
	offset := len(defaultHDInfo)
	binary.BigEndian.PutUint32(info[offset:offset+4], account)
	binary.BigEndian.PutUint32(info[offset+4:offset+8], branch)
	binary.BigEndian.PutUint32(info[offset+8:offset+12], index)
	reader := hkdf.New(sha3.New256, masterSeed[:], nil, info)
	var seed [mldsa87.SeedSize]byte
	if _, err := io.ReadFull(reader, seed[:]); err != nil {
		return nil, fmt.Errorf("derive path seed: %w", err)
	}
	return &seed, nil
}

func KeyMaterialFromPath(masterSeed *[mldsa87.SeedSize]byte, account, branch, index uint32) (*KeyMaterial, error) {
	seed, err := DerivePathSeed(masterSeed, account, branch, index)
	if err != nil {
		return nil, err
	}
	return KeyMaterialFromSeed(seed)
}

func KeyMaterialFromKeyPair(pk *mldsa87.PublicKey, sk *mldsa87.PrivateKey) (*KeyMaterial, error) {
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	publicKeyHex := strings.ToLower(hex.EncodeToString(pkBytes))
	address, err := deriveSingleSigAddress(publicKeyHex)
	if err != nil {
		return nil, err
	}
	return &KeyMaterial{
		PrivateKeyHex: strings.ToLower(hex.EncodeToString(skBytes)),
		PublicKeyHex:  publicKeyHex,
		SeedHex:       strings.ToLower(hex.EncodeToString(sk.Seed())),
		Address:       address,
	}, nil
}

func deriveSingleSigAddress(publicKeyHex string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(publicKeyHex))
	if normalized == "" {
		return "", fmt.Errorf("public key is required")
	}
	return chain.PolicyAddress(1, []string{normalized})
}
