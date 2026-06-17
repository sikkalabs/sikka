package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"besoeasy/sikka/internal/chain"
)

const (
	defaultAPIPort      = 64552
	defaultSyncInterval = 180
	defaultDataDir      = "/home/sikka/data"
	envNodePrivateKey   = "nodeprivatekey"
	envNodeAddress      = "nodeaddress"
	envNodeMessage    = "nodemessage"
	maxNodeMessageLen = 100
)

const defaultTorSocksAddress = "127.0.0.1:19050"
const defaultTorControlAddress = "127.0.0.1:19051"
const defaultTorHiddenServicePort = 80

var defaultBootstrapSyncSeeds = []string{
	"http://5t6u742nvbuqlfeuzueiqcbifkepcfbr7nz2mvofdmusnxtrk3w2oaqd.onion",
	"http://3ruudes3awwz6vny6kp2tusri6hdr3ezf2ewxvwqwpjmeh6gu7q5flid.onion",
}

type Config struct {
	APIPort             int
	SyncIntervalSeconds int
	DataDir             string
	SyncSeeds           []string
	NodePrivateKey      string
	// NodeAddress is an optional Sikka bech32m donation address (sikka1…).
	// When empty, the API returns an empty string so UIs can hide the field.
	NodeAddress string
	// NodeMessage is an optional short status blurb (letters, digits, spaces, periods).
	// When empty, status surfaces use "SIKKA " plus the embedded software version.
	NodeMessage string
}

func LoadFromEnv() (Config, error) {
	apiPort := defaultAPIPort

	dataDir := defaultDataDir
	syncSeeds := append([]string(nil), defaultBootstrapSyncSeeds...)
	nodePrivateKey := strings.TrimSpace(os.Getenv(envNodePrivateKey))
	if nodePrivateKey != "" {
		normalized, err := normalizeNodePrivateKey(nodePrivateKey)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s value: %w", envNodePrivateKey, err)
		}
		nodePrivateKey = normalized
	}

	nodeAddress, err := normalizeNodeAddress(os.Getenv(envNodeAddress))
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s value: %w", envNodeAddress, err)
	}
	nodeMessage, err := normalizeNodeMessage(os.Getenv(envNodeMessage))
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s value: %w", envNodeMessage, err)
	}

	return Config{
		APIPort:             apiPort,
		SyncIntervalSeconds: defaultSyncInterval,
		DataDir:             dataDir,
		SyncSeeds:           syncSeeds,
		NodePrivateKey:      nodePrivateKey,
		NodeAddress:         nodeAddress,
		NodeMessage:         nodeMessage,
	}, nil
}

func normalizeNodeAddress(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	normalized, err := chain.NormalizeAddress(value)
	if err != nil {
		return "", fmt.Errorf("%s must be a valid sikka1… address: %w", envNodeAddress, err)
	}
	return normalized, nil
}

func normalizeNodeMessage(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > maxNodeMessageLen {
		return "", fmt.Errorf("%s must be at most %d characters", envNodeMessage, maxNodeMessageLen)
	}
	for index, char := range value {
		if char > 127 {
			return "", fmt.Errorf("%s must contain only ASCII letters, digits, spaces, and periods", envNodeMessage)
		}
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == ' ':
		case char == '.':
		default:
			return "", fmt.Errorf("%s must contain only ASCII letters, digits, spaces, and periods (invalid character at position %d)", envNodeMessage, index+1)
		}
	}
	return value, nil
}

func normalizeNodePrivateKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("value is required")
	}
	if len(raw) == 64 {
		if _, err := hex.DecodeString(raw); err == nil {
			return strings.ToLower(raw), nil
		}
	}
	return raw, nil
}

func NodePrivateKeySeed(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("value is required")
	}
	if len(raw) == 64 {
		if decoded, err := hex.DecodeString(raw); err == nil {
			return decoded, nil
		}
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], nil
}

func normalizeNodeURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("host is required")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("query and fragment are not allowed")
	}
	parsed.Path = strings.TrimRight(parsed.EscapedPath(), "/")
	if parsed.Path == "." {
		parsed.Path = ""
	}
	return parsed.String(), nil
}

func (c Config) APIListenAddress() string {
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(c.APIPort))
}

func (c Config) TorSocksAddress() string {
	return defaultTorSocksAddress
}

func (c Config) TorControlAddress() string {
	return defaultTorControlAddress
}

func (c Config) TorDataDir() string {
	baseDataDir := c.DataDir
	if strings.TrimSpace(baseDataDir) == "" {
		baseDataDir = defaultDataDir
	}
	return filepath.Join(baseDataDir, "tor")
}

func (c Config) TorHiddenServicePort() int {
	return defaultTorHiddenServicePort
}
