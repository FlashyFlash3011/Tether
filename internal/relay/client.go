package relay

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/gorilla/websocket"
)

// Client connects to a relay Server via WebSocket and bridges WireGuard
// UDP packets over the connection. It runs on the Mac.
type Client struct {
	wgListenPort int
}

// NewClient creates a relay Client.
// wgListenPort is the port WireGuard is listening on locally (typically 51820).
func NewClient(wgListenPort int) *Client {
	return &Client{wgListenPort: wgListenPort}
}

// Connect dials the relay server at wsURL and starts bridging.
// wsURL should be the cloudflared WSS URL, e.g. wss://xyz.trycloudflare.com/ws
// Blocks until the connection drops.
func (c *Client) Connect(wsURL string) error {
	// Normalise http(s) → ws(s)
	wsURL = toWSS(wsURL)

	log.Printf("relay: connecting to %s", wsURL)
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("relay: dial %s: %w", wsURL, err)
	}
	defer ws.Close()
	log.Printf("relay: connected")

	// Bind local UDP socket on RelayUDPPort.
	// We configure WireGuard to send to this port as the PC peer's endpoint.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: RelayUDPPort,
	})
	if err != nil {
		return fmt.Errorf("relay: bind UDP: %w", err)
	}
	defer udpConn.Close()

	wgAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: c.wgListenPort,
	}

	log.Printf("relay: bridging UDP 127.0.0.1:%d ↔ WebSocket", RelayUDPPort)
	bridge(udpConn, wgAddr, ws)
	return nil
}

// RelayEndpoint returns the WireGuard peer endpoint to use when relay is active.
func RelayEndpoint() string {
	return fmt.Sprintf("127.0.0.1:%d", RelayUDPPort)
}

func toWSS(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + u[len("https://"):] + "/ws"
	case strings.HasPrefix(u, "http://"):
		return "ws://" + u[len("http://"):] + "/ws"
	case strings.HasPrefix(u, "wss://") || strings.HasPrefix(u, "ws://"):
		return u
	default:
		return "wss://" + u + "/ws"
	}
}
