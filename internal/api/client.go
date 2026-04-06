// Package api provides an HTTP client for the Tether coordination Worker.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/FlashyFlash3011/tether/internal/auth"
)

// PeerInfo is a single peer record returned by GET /peers.
type PeerInfo struct {
	NodeID   string `json:"node_id"`
	Pubkey   string `json:"pubkey"`
	VPNAddr  string `json:"vpn_addr"`
	Endpoint string `json:"endpoint"` // "ip:port"
}

// Client talks to the coordination Worker.
type Client struct {
	serverURL  string
	nodeID     string
	secret     []byte
	httpClient *http.Client
}

// New creates a Client.
// secret is the HMAC-HS256 key for this node (raw bytes, 32 bytes recommended).
func New(serverURL, nodeID string, secret []byte) *Client {
	return &Client{
		serverURL: serverURL,
		nodeID:    nodeID,
		secret:    secret,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Register POSTs this node's public key and listen port to the Worker.
// The Worker derives the external endpoint as CF-Connecting-IP:listenPort.
func (c *Client) Register(pubkeyBase64 string, listenPort int) error {
	body, _ := json.Marshal(map[string]any{
		"pubkey":      pubkeyBase64,
		"listen_port": listenPort,
	})
	resp, err := c.do(http.MethodPost, "/register", body)
	if err != nil {
		return fmt.Errorf("api: register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api: register: server returned %d: %s", resp.StatusCode, msg)
	}
	return nil
}

// GetPeers fetches all peers except this node.
func (c *Client) GetPeers() ([]PeerInfo, error) {
	resp, err := c.do(http.MethodGet, "/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("api: get peers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api: get peers: server returned %d: %s", resp.StatusCode, msg)
	}
	var result struct {
		Peers []PeerInfo `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("api: get peers: decode response: %w", err)
	}
	return result.Peers, nil
}

// RelaySessionURL returns the WebSocket URL for a relay session.
func (c *Client) RelaySessionURL(sessionID string) string {
	// Convert https:// → wss://
	url := c.serverURL
	switch {
	case len(url) >= 8 && url[:8] == "https://":
		url = "wss://" + url[8:]
	case len(url) >= 7 && url[:7] == "http://":
		url = "ws://" + url[7:]
	}
	return url + "/relay/" + sessionID
}

// do executes an authenticated HTTP request to the Worker.
// A fresh JWT is minted for every request (5-min TTL, short-lived by design).
func (c *Client) do(method, path string, body []byte) (*http.Response, error) {
	token, err := auth.NewToken(c.nodeID, c.secret)
	if err != nil {
		return nil, fmt.Errorf("api: mint token: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, c.serverURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("api: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}
