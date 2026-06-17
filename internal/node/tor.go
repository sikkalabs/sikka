package node

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"besoeasy/sikka/internal/config"

	"golang.org/x/crypto/sha3"
)

const torOnionVersion = byte(0x03)

type torControlClient struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

type torNetworkHealth struct {
	NetworkHealth      string
	BootstrapProgress  int
	BootstrapTag       string
	BootstrapSummary   string
	BootstrapWarning   string
	CircuitEstablished bool
}

var torControlFieldPattern = regexp.MustCompile(`([A-Z_]+)=("[^"]*"|[^ ]+)`)

type onionServiceIdentity struct {
	Hostname string
	URL      string
	KeyBlob  string
}

func managedTorArgs(cfg config.Config) []string {
	dataDir := cfg.TorDataDir()
	torLog := filepath.Join(dataDir, "tor.log")
	return []string{
		"--SocksPort", cfg.TorSocksAddress(),
		"--ControlPort", cfg.TorControlAddress(),
		"--CookieAuthentication", "0",
		"--DataDirectory", dataDir,
		// Send detailed logs to a file (useful for debugging Tor issues without
		// polluting the node's console). Only send errors to stderr (which the
		// node discards).
		"--Log", "notice file " + torLog,
		"--Log", "err stderr",
	}
}

func onionServiceIdentityFromSeed(seed []byte) (onionServiceIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return onionServiceIdentity{}, fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return onionServiceIdentity{}, fmt.Errorf("derive public key: unexpected key type")
	}
	serviceID, err := onionServiceID(publicKey)
	if err != nil {
		return onionServiceIdentity{}, err
	}
	hostname := serviceID + ".onion"
	keyBlob := torOnionKeyBlob(seed)
	return onionServiceIdentity{Hostname: hostname, URL: "http://" + hostname, KeyBlob: keyBlob}, nil
}

func torOnionKeyBlob(seed []byte) string {
	expanded := sha512.Sum512(seed)
	secretScalar := append([]byte(nil), expanded[:32]...)
	secretScalar[0] &= 248
	secretScalar[31] &= 63
	secretScalar[31] |= 64
	keyBytes := append(secretScalar, expanded[32:64]...)
	return base64.StdEncoding.EncodeToString(keyBytes)
}

func onionServiceID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	checksumInput := make([]byte, 0, len(".onion checksum")+len(publicKey)+1)
	checksumInput = append(checksumInput, []byte(".onion checksum")...)
	checksumInput = append(checksumInput, publicKey...)
	checksumInput = append(checksumInput, torOnionVersion)
	checksum := sha3.Sum256(checksumInput)
	addressBytes := make([]byte, 0, len(publicKey)+3)
	addressBytes = append(addressBytes, publicKey...)
	addressBytes = append(addressBytes, checksum[:2]...)
	addressBytes = append(addressBytes, torOnionVersion)
	serviceID := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addressBytes)
	return strings.ToLower(serviceID), nil
}

func (n *Node) startManagedTor(ctx context.Context) error {
	if err := os.MkdirAll(n.config.TorDataDir(), 0o700); err != nil {
		return fmt.Errorf("create tor data dir: %w", err)
	}
	cmd := exec.CommandContext(ctx, "tor", managedTorArgs(n.config)...)
	// Suppress Tor's very verbose stdout/stderr (bootstrap progress, circuit
	// status, etc.). These were mixing with the node's own logs and making
	// it hard to see real application output. High-level Tor status is still
	// emitted via structured slog calls on the node logger.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start managed tor: %w", err)
	}
	n.torCmd = cmd
	go func() {
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			n.log.Warn("managed tor exited", "err", err)
		}
	}()
	if err := waitForTCP(n.config.TorSocksAddress(), 15*time.Second); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("wait for tor socks listener: %w", err)
	}
	if err := waitForTCP(n.config.TorControlAddress(), 15*time.Second); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("wait for tor control listener: %w", err)
	}
	control, err := connectTorControl(n.config.TorControlAddress())
	if err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("connect tor control: %w", err)
	}
	serviceID, err := control.addOnion(n.torOnionKey, n.config.TorHiddenServicePort(), net.JoinHostPort("127.0.0.1", strconv.Itoa(n.config.APIPort)))
	if err != nil {
		_ = control.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("create managed onion service: %w", err)
	}
	expectedServiceID := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(n.onionPublicURL), "http://"), ".onion")
	if serviceID != expectedServiceID {
		_ = control.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("managed onion service id mismatch: got %s want %s", serviceID, expectedServiceID)
	}
	n.torControlMu.Lock()
	n.torControl = control
	n.torControlMu.Unlock()
	n.log.Info("managed tor hidden service", "onion_url", n.onionPublicURL)
	n.log.Info("managed tor started", "socks", n.config.TorSocksAddress())
	return nil
}

func connectTorControl(address string) (*torControlClient, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	client := &torControlClient{conn: conn, reader: bufio.NewReader(conn)}
	if _, err := client.command("AUTHENTICATE"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *torControlClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *torControlClient) addOnion(keyBlob string, virtualPort int, target string) (string, error) {
	replies, err := c.command(fmt.Sprintf("ADD_ONION ED25519-V3:%s Port=%d,%s", keyBlob, virtualPort, target))
	if err != nil {
		return "", err
	}
	for _, reply := range replies {
		if value, ok := strings.CutPrefix(reply, "ServiceID="); ok {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("missing ServiceID in tor response")
}

func (c *torControlClient) command(command string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := fmt.Fprintf(c.conn, "%s\r\n", command); err != nil {
		return nil, err
	}
	var replies []string
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return nil, fmt.Errorf("short tor control reply: %q", line)
		}
		status := line[:3]
		if status[0] != '2' {
			return nil, fmt.Errorf("tor control %s failed: %s", command, line)
		}
		if len(line) == 3 {
			return replies, nil
		}
		separator := line[3]
		payload := strings.TrimSpace(line[4:])
		if payload != "OK" && payload != "" {
			replies = append(replies, payload)
		}
		if separator == ' ' {
			return replies, nil
		}
		if separator != '-' {
			return nil, fmt.Errorf("unexpected tor control reply: %q", line)
		}
	}
}

func (c *torControlClient) networkHealth() (torNetworkHealth, error) {
	bootstrapReplies, err := c.command("GETINFO status/bootstrap-phase")
	if err != nil {
		return torNetworkHealth{}, err
	}
	circuitReplies, err := c.command("GETINFO status/circuit-established")
	if err != nil {
		return torNetworkHealth{}, err
	}
	return parseTorNetworkHealth(bootstrapReplies, circuitReplies), nil
}

func parseTorNetworkHealth(bootstrapReplies, circuitReplies []string) torNetworkHealth {
	health := torNetworkHealth{NetworkHealth: "starting"}

	for _, reply := range bootstrapReplies {
		value := reply
		if trimmed, ok := strings.CutPrefix(value, "status/bootstrap-phase="); ok {
			value = trimmed
		}
		fields := parseTorControlFields(value)
		if progress, err := strconv.Atoi(fields["PROGRESS"]); err == nil {
			health.BootstrapProgress = progress
		}
		health.BootstrapTag = fields["TAG"]
		health.BootstrapSummary = fields["SUMMARY"]
		health.BootstrapWarning = fields["WARNING"]
		if health.BootstrapWarning == "" {
			health.BootstrapWarning = fields["REASON"]
		}
		break
	}

	for _, reply := range circuitReplies {
		value := reply
		if trimmed, ok := strings.CutPrefix(value, "status/circuit-established="); ok {
			value = trimmed
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes":
			health.CircuitEstablished = true
		}
		break
	}

	switch {
	case health.BootstrapProgress >= 100:
		health.NetworkHealth = "connected"
	case health.BootstrapProgress > 0:
		health.NetworkHealth = "bootstrapping"
	}

	return health
}

func parseTorControlFields(raw string) map[string]string {
	fields := make(map[string]string)
	for _, match := range torControlFieldPattern.FindAllStringSubmatch(raw, -1) {
		value := strings.Trim(match[2], `"`)
		fields[match[1]] = value
	}
	return fields
}

func (n *Node) currentTorControl() *torControlClient {
	n.torControlMu.RLock()
	defer n.torControlMu.RUnlock()
	return n.torControl
}

func waitForTCP(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", address)
}
