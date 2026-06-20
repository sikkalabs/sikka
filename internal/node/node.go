package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"besoeasy/sikka/internal/chain"
	"besoeasy/sikka/internal/config"

	"golang.org/x/net/proxy"
)

type Node struct {
	log            *slog.Logger
	config         config.Config
	onionPublicURL string
	torOnionKey    string
	dag            *chain.DAG
	http           *http.Server
	torHTTPClient  *http.Client
	knownNodes     map[string]*nodeRecord
	nodeBookMu     sync.RWMutex
	syncStateMu    sync.RWMutex
	torControlMu   sync.RWMutex
	lastSyncAt     time.Time
	lastSyncSource string
	lastSyncError  string
	torCmd         *exec.Cmd
	torControl     *torControlClient

	publicDir     string
	publicHandler http.Handler
}

const (
	nodePrivateKeyFileName = "nodeprivatekey"

	// maxRequestBodyBytes caps the size of POST request bodies to prevent
	// memory exhaustion attacks.
	maxRequestBodyBytes = 1 << 20 // 1 MiB
)

func New(cfg config.Config) (*Node, error) {
	dag, err := chain.NewDAG(chain.Options{DataDir: cfg.DataDir})
	if err != nil {
		return nil, fmt.Errorf("create dag: %w", err)
	}
	nodeSeed, err := loadOrCreateNodePrivateKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("load node private key: %w", err)
	}
	identity, err := onionServiceIdentityFromSeed(nodeSeed)
	if err != nil {
		return nil, fmt.Errorf("derive onion identity: %w", err)
	}
	torHTTPClient, err := newOutboundHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	node := &Node{
		log:            initNodeLogger(),
		config:         cfg,
		onionPublicURL: identity.URL,
		torOnionKey:    identity.KeyBlob,
		dag:            dag,
		torHTTPClient:  torHTTPClient,
		knownNodes:     make(map[string]*nodeRecord),
	}
	if err := node.loadNodeBook(); err != nil {
		return nil, fmt.Errorf("load node book: %w", err)
	}
	for _, nodeURL := range cfg.SyncSeeds {
		if _, _, err := node.addKnownNode(nodeURL, true, false); err != nil {
			return nil, fmt.Errorf("bootstrap node %q: %w", nodeURL, err)
		}
	}
	node.log.Info("known peers at start", "count", len(node.knownNodes), "bootstrap_seeds", len(cfg.SyncSeeds))
	node.http = &http.Server{
		Addr:              cfg.APIListenAddress(),
		Handler:           node.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return node, nil
}

func loadOrCreateNodePrivateKey(cfg config.Config) ([]byte, error) {
	if strings.TrimSpace(cfg.NodePrivateKey) != "" {
		return config.NodePrivateKeySeed(cfg.NodePrivateKey)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(cfg.DataDir, nodePrivateKeyFileName)
	payload, err := os.ReadFile(path)
	if err == nil {
		stored := strings.TrimSpace(string(payload))
		if stored != "" {
			return config.NodePrivateKeySeed(stored)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	randomBytes := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(randomBytes)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func newOutboundHTTPClient(cfg config.Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer, err := proxy.SOCKS5("tcp", cfg.TorSocksAddress(), nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer: %w", err)
	}
	transport.Proxy = nil
	transport.DialContext = nil
	transport.Dial = dialer.Dial
	transport.ResponseHeaderTimeout = peerResponseHeaderTimeout
	return &http.Client{
		Timeout:   outboundRequestTimeout,
		Transport: transport,
	}, nil
}

func (n *Node) advertisedAddresses() []string {
	if strings.TrimSpace(n.onionPublicURL) == "" {
		return nil
	}
	return []string{n.onionPublicURL}
}

func (n *Node) outboundHTTPClient() *http.Client {
	return n.torHTTPClient
}
func (n *Node) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if err := n.dag.Close(); err != nil {
			n.log.Error("close dag", "err", err)
		}
	}()
	if err := n.startManagedTor(runCtx); err != nil {
		return err
	}
	defer func() {
		n.torControlMu.Lock()
		control := n.torControl
		n.torControl = nil
		n.torControlMu.Unlock()
		if control != nil {
			_ = control.Close()
		}
	}()

	n.log.Info("sikka node starting",
		"api", n.config.APIListenAddress(),
		"federation_nodes", len(n.config.SyncSeeds),
	)
	n.log.Info("managed tor enabled", "socks", n.config.TorSocksAddress())
	n.log.Info("local dag",
		"size", n.dag.Size(),
		"genesis", n.dag.GenesisID(),
	)
	n.log.Info("discovery loop", "interval", "15m")

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := n.runHTTP(); err != nil {
			errCh <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.runSyncLoop(runCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.runDiscoveryLoop(runCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.pruneKnownNodesLoop(runCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.runWitnessSweepLoop(runCtx)
	}()

	select {
	case err := <-errCh:
		cancel()
		_ = n.shutdownHTTP()
		wg.Wait()
		return err
	case <-ctx.Done():
	}

	cancel()
	n.log.Info("sikka node shutting down")
	if err := n.shutdownHTTP(); err != nil {
		return err
	}
	wg.Wait()

	return ctx.Err()
}
