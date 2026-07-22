package config

import (
	"strings"
	"testing"
)

func TestConfigListenAddresses(t *testing.T) {
	t.Parallel()

	cfg := Config{APIPort: 64552}

	if got, want := cfg.APIListenAddress(), "0.0.0.0:64552"; got != want {
		t.Fatalf("APIListenAddress() = %q, want %q", got, want)
	}
	if got, want := cfg.TorDataDir(), "/home/sikka/data/tor"; got != want {
		t.Fatalf("TorDataDir() = %q, want %q", got, want)
	}
	if got, want := cfg.TorControlAddress(), "127.0.0.1:19051"; got != want {
		t.Fatalf("TorControlAddress() = %q, want %q", got, want)
	}
	if got, want := cfg.TorHiddenServicePort(), 80; got != want {
		t.Fatalf("TorHiddenServicePort() = %d, want %d", got, want)
	}
}

func TestLoadFromEnvUsesConfiguredBootstrapSeeds(t *testing.T) {
	originalBootstrapSeeds := append([]string(nil), defaultBootstrapSyncSeeds...)
	defaultBootstrapSyncSeeds = []string{"https://seed-one.example.com", "http://seed-two.example.com:64552"}
	t.Cleanup(func() { defaultBootstrapSyncSeeds = originalBootstrapSeeds })

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if len(cfg.SyncSeeds) != 2 {
		t.Fatalf("len(cfg.SyncSeeds) = %d, want 2", len(cfg.SyncSeeds))
	}
	if cfg.SyncSeeds[0] != "https://seed-one.example.com" {
		t.Fatalf("cfg.SyncSeeds[0] = %q, want %q", cfg.SyncSeeds[0], "https://seed-one.example.com")
	}
	if cfg.SyncSeeds[1] != "http://seed-two.example.com:64552" {
		t.Fatalf("cfg.SyncSeeds[1] = %q, want %q", cfg.SyncSeeds[1], "http://seed-two.example.com:64552")
	}
}

func TestLoadFromEnvIgnoresFixedDockerPortsAndDataDir(t *testing.T) {
	t.Setenv("SIKKA_API_PORT", "9999")
	t.Setenv("SIKKA_DATA_DIR", "/tmp/custom-data")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if cfg.APIPort != 64552 {
		t.Fatalf("cfg.APIPort = %d, want 64552", cfg.APIPort)
	}
	if cfg.SyncIntervalSeconds != defaultSyncInterval {
		t.Fatalf("cfg.SyncIntervalSeconds = %d, want %d", cfg.SyncIntervalSeconds, defaultSyncInterval)
	}
	if cfg.DataDir != "/home/sikka/data" {
		t.Fatalf("cfg.DataDir = %q, want %q", cfg.DataDir, "/home/sikka/data")
	}
}

func TestLoadFromEnvUsesDefaultBootstrapSyncSeed(t *testing.T) {
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if len(cfg.SyncSeeds) != len(defaultBootstrapSyncSeeds) {
		t.Fatalf("len(cfg.SyncSeeds) = %d, want %d", len(cfg.SyncSeeds), len(defaultBootstrapSyncSeeds))
	}
	for i, want := range defaultBootstrapSyncSeeds {
		if cfg.SyncSeeds[i] != want {
			t.Fatalf("cfg.SyncSeeds[%d] = %q, want %q", i, cfg.SyncSeeds[i], want)
		}
	}
}

func TestLoadFromEnvUsesManagedTorDefaults(t *testing.T) {
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if cfg.TorDataDir() != "/home/sikka/data/tor" {
		t.Fatalf("cfg.TorDataDir() = %q, want %q", cfg.TorDataDir(), "/home/sikka/data/tor")
	}
	if cfg.TorHiddenServicePort() != 80 {
		t.Fatalf("cfg.TorHiddenServicePort() = %d, want 80", cfg.TorHiddenServicePort())
	}
}

func TestLoadFromEnvUsesConfiguredNodePrivateKey(t *testing.T) {
	t.Setenv("nodeprivatekey", "4f8c2b7f9e0a1d3c5b6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if got, want := cfg.NodePrivateKey, "4f8c2b7f9e0a1d3c5b6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4"; got != want {
		t.Fatalf("cfg.NodePrivateKey = %q, want %q", got, want)
	}
}

func TestNodePrivateKeySeedSupportsHexAndText(t *testing.T) {
	t.Parallel()

	hexSeed, err := NodePrivateKeySeed("4f8c2b7f9e0a1d3c5b6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4")
	if err != nil {
		t.Fatalf("NodePrivateKeySeed(hex) error = %v", err)
	}
	if len(hexSeed) != 32 {
		t.Fatalf("len(hexSeed) = %d, want 32", len(hexSeed))
	}
	textSeedA, err := NodePrivateKeySeed("my-deterministic-node-key")
	if err != nil {
		t.Fatalf("NodePrivateKeySeed(text A) error = %v", err)
	}
	textSeedB, err := NodePrivateKeySeed("my-deterministic-node-key")
	if err != nil {
		t.Fatalf("NodePrivateKeySeed(text B) error = %v", err)
	}
	if string(textSeedA) != string(textSeedB) {
		t.Fatal("expected text-derived node private key seed to be deterministic")
	}
}

func TestLoadFromEnvRejectsInvalidNodeDisplayFields(t *testing.T) {
	t.Setenv(envNodeAddress, "myseed01")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected invalid nodeaddress to fail")
	}

	t.Setenv(envNodeAddress, "")
	t.Setenv(envNodeMessage, "hello\nworld")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected invalid nodemessage to fail")
	}

	t.Setenv(envNodeMessage, strings.Repeat("a", maxNodeMessageLen+1))
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected overlong nodemessage to fail")
	}
}

func TestLoadFromEnvAcceptsNodeDisplayFields(t *testing.T) {
	donationAddress := "sikka1p4ktc4mcwzekfauhw2eeqfx5edeffaqtmcv3qaautjkrh55slgrmswvkjvf"
	t.Setenv(envNodeAddress, donationAddress)
	t.Setenv(envNodeMessage, "SIKKA relay v0.0.31")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if cfg.NodeAddress != donationAddress {
		t.Fatalf("cfg.NodeAddress = %q, want %q", cfg.NodeAddress, donationAddress)
	}
	if cfg.NodeMessage != "SIKKA relay v0.0.31" {
		t.Fatalf("cfg.NodeMessage = %q, want %q", cfg.NodeMessage, "SIKKA relay v0.0.31")
	}
}


