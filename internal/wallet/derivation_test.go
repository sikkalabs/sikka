package wallet

import "testing"

func TestKeyMaterialFromMnemonicGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mnemonic   string
		passphrase string
		address    string
	}{
		{
			name:       "no passphrase",
			mnemonic:   "gloom ice air over evolve predict bicycle column route minor donor welcome elephant produce lounge boss skirt often snap neutral sick sauce kangaroo poet",
			passphrase: "",
			address:    "sikka1p4ktc4mcwzekfauhw2eeqfx5edeffaqtmcv3qaautjkrh55slgrmswvkjvf",
		},
		{
			name:       "with passphrase",
			mnemonic:   "spike flush torch clown execute purpose valid online prevent melody once exchange token uncover enhance step clog cross smooth split dinosaur funny enemy follow",
			passphrase: "test-passphrase-123",
			address:    "sikka1par3yv7w5fqjyx897ucud97yhc5aalgtanjrpsg68rltqtnxhplls5w47fw",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			material, err := KeyMaterialFromMnemonic(tc.mnemonic, tc.passphrase)
			if err != nil {
				t.Fatalf("KeyMaterialFromMnemonic() error = %v", err)
			}
			if material.Address != tc.address {
				t.Fatalf("KeyMaterialFromMnemonic() address = %q, want %q", material.Address, tc.address)
			}

			seed, err := SeedFromMnemonic(tc.mnemonic, tc.passphrase)
			if err != nil {
				t.Fatalf("SeedFromMnemonic() error = %v", err)
			}
			fromSeed, err := KeyMaterialFromSeed(seed)
			if err != nil {
				t.Fatalf("KeyMaterialFromSeed() error = %v", err)
			}
			if fromSeed.Address != tc.address {
				t.Fatalf("KeyMaterialFromSeed() address = %q, want %q", fromSeed.Address, tc.address)
			}
			if fromSeed.Address != material.Address {
				t.Fatalf("seed path address = %q, mnemonic path address = %q", fromSeed.Address, material.Address)
			}
		})
	}
}

func TestNormalizeMnemonicFormatting(t *testing.T) {
	t.Parallel()

	canonical := "gloom ice air over evolve predict bicycle column route minor donor welcome elephant produce lounge boss skirt often snap neutral sick sauce kangaroo poet"
	messy := "  GLOOM   ice AIR over evolve predict bicycle column route minor donor welcome elephant produce lounge boss skirt often snap neutral sick sauce kangaroo poet  "

	canonicalMaterial, err := KeyMaterialFromMnemonic(canonical, "")
	if err != nil {
		t.Fatalf("KeyMaterialFromMnemonic(canonical) error = %v", err)
	}
	messyMaterial, err := KeyMaterialFromMnemonic(messy, "")
	if err != nil {
		t.Fatalf("KeyMaterialFromMnemonic(messy) error = %v", err)
	}
	if messyMaterial.Address != canonicalMaterial.Address {
		t.Fatalf("normalized mnemonic address = %q, want %q", messyMaterial.Address, canonicalMaterial.Address)
	}
}

func TestKeyMaterialFromPathDeterministic(t *testing.T) {
	t.Parallel()

	mnemonic := "gloom ice air over evolve predict bicycle column route minor donor welcome elephant produce lounge boss skirt often snap neutral sick sauce kangaroo poet"
	masterSeed, err := SeedFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic() error = %v", err)
	}

	first, err := KeyMaterialFromPath(masterSeed, 0, ExternalChain, 0)
	if err != nil {
		t.Fatalf("KeyMaterialFromPath(first) error = %v", err)
	}
	second, err := KeyMaterialFromPath(masterSeed, 0, ExternalChain, 0)
	if err != nil {
		t.Fatalf("KeyMaterialFromPath(second) error = %v", err)
	}

	if first.Address != second.Address {
		t.Fatalf("receive path address mismatch: %q != %q", first.Address, second.Address)
	}
	if first.PrivateKeyHex != second.PrivateKeyHex {
		t.Fatalf("receive path private key mismatch")
	}
}

func TestKeyMaterialFromPathSeparatesBranches(t *testing.T) {
	t.Parallel()

	mnemonic := "gloom ice air over evolve predict bicycle column route minor donor welcome elephant produce lounge boss skirt often snap neutral sick sauce kangaroo poet"
	masterSeed, err := SeedFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic() error = %v", err)
	}

	receive0, err := KeyMaterialFromPath(masterSeed, 0, ExternalChain, 0)
	if err != nil {
		t.Fatalf("KeyMaterialFromPath(receive0) error = %v", err)
	}
	receive1, err := KeyMaterialFromPath(masterSeed, 0, ExternalChain, 1)
	if err != nil {
		t.Fatalf("KeyMaterialFromPath(receive1) error = %v", err)
	}
	change0, err := KeyMaterialFromPath(masterSeed, 0, InternalChain, 0)
	if err != nil {
		t.Fatalf("KeyMaterialFromPath(change0) error = %v", err)
	}

	if receive0.Address == receive1.Address {
		t.Fatalf("receive branch reused address for different index: %q", receive0.Address)
	}
	if receive0.Address == change0.Address {
		t.Fatalf("receive and change branches reused address: %q", receive0.Address)
	}
	if receive1.Address == change0.Address {
		t.Fatalf("receive and change branches reused address: %q", receive1.Address)
	}
}
