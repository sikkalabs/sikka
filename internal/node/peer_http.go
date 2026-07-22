package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (n *Node) getJSON(ctx context.Context, endpoint string, payload any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := n.outboundHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("http %d from %s: %s", resp.StatusCode, endpoint, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(payload); err != nil {
		n.penalizeNode(endpoint, PenaltyInvalidPayload, "invalid JSON response")
		return err
	}
	n.recordPeerLatency(endpoint, time.Since(start))
	return nil
}

func (n *Node) postJSONAndDecode(ctx context.Context, endpoint string, reqPayload any, respPayload any) error {
	body, err := json.Marshal(reqPayload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := n.outboundHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("http %d from %s: %s", resp.StatusCode, endpoint, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(respPayload); err != nil {
		n.penalizeNode(endpoint, PenaltyInvalidPayload, "invalid JSON response")
		return err
	}
	n.recordPeerLatency(endpoint, time.Since(start))
	return nil
}
func (n *Node) postJSON(ctx context.Context, endpoint string, payload any, relay relayContext) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if relay.origin != "" {
		req.Header.Set(relayHeaderOrigin, relay.origin)
	}
	if relay.sender != "" {
		req.Header.Set(relayHeaderSender, relay.sender)
	}
	req.Header.Set(relayHeaderHop, strconv.Itoa(relay.hop))

	start := time.Now()
	resp, err := n.outboundHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		n.recordPeerLatency(endpoint, time.Since(start))
		return nil
	}
	bodyText, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	trimmed := strings.TrimSpace(string(bodyText))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(trimmed, "already") {
		return nil
	}
	return fmt.Errorf("http %d from %s: %s", resp.StatusCode, endpoint, trimmed)
}
