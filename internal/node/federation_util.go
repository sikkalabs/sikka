package node

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

func nextNodeRetryDelay(failureCount int) time.Duration {
	if failureCount <= 0 {
		return nodeFailureBackoffBase
	}
	delay := nodeFailureBackoffBase
	for i := 1; i < failureCount; i++ {
		delay += delay / 2 // 1.5x backoff multiplier
		if delay >= nodeFailureBackoffMax {
			return nodeFailureBackoffMax
		}
	}
	if delay > nodeFailureBackoffMax {
		return nodeFailureBackoffMax
	}
	return delay
}

func (n *Node) nextSyncLoopDelay() time.Duration {
	base := time.Duration(n.config.SyncIntervalSeconds) * time.Second
	if base <= 0 {
		base = 180 * time.Second
	}
	jitter := base / 5 // 20%
	minDelay := base - jitter
	span := int64(jitter * 2)
	if span <= 0 {
		return minDelay
	}
	return minDelay + time.Duration(cryptoRandInt63n(span+1))
}

func waitForFederationDelay(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func shuffleStrings(values []string) {
	// Crypto-backed Fisher–Yates shuffle so peer-selection order is not
	// predictable to a passive observer.
	for i := len(values) - 1; i > 0; i-- {
		j := int(cryptoRandInt63n(int64(i + 1)))
		values[i], values[j] = values[j], values[i]
	}
}

// cryptoRandInt63n returns an unbiased random int64 in [0, n) using
// crypto/rand. It panics if n <= 0 or if the system RNG fails.
func cryptoRandInt63n(n int64) int64 {
	if n <= 0 {
		panic(fmt.Sprintf("cryptoRandInt63n: n must be positive, got %d", n))
	}
	v, err := cryptorand.Int(cryptorand.Reader, big.NewInt(n))
	if err != nil {
		panic(fmt.Sprintf("cryptoRandInt63n: crypto/rand failed: %v", err))
	}
	return v.Int64()
}

// cryptoRandIntn returns an unbiased random int in [0, n).
func cryptoRandIntn(n int) int {
	return int(cryptoRandInt63n(int64(n)))
}

func normalizeDiscoveredNodeURL(raw string) (string, error) {
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

func isOnionNodeURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.Contains(strings.ToLower(raw), ".onion")
	}
	return strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".onion")
}

func joinNodeURL(base, path string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	return parsed.ResolveReference(ref).String()
}
