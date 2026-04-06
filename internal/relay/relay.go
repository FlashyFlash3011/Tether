// Package relay implements a UDP↔WebSocket bridge for relaying WireGuard
// packets when direct UDP hole-punching fails.
//
// Each WireGuard UDP packet is sent as a single binary WebSocket message.
// The relay is transparent: it forwards raw WireGuard ciphertext, providing
// no decryption or inspection. End-to-end security is guaranteed by WireGuard.
//
// Architecture:
//
//	PC side (Server):
//	  WireGuard → UDP:relayPort ←→ WebSocket server (via cloudflared) ←→ Mac
//
//	Mac side (Client):
//	  WireGuard → UDP:relayPort ←→ WebSocket client ←→ cloudflared ←→ PC
package relay

import "net"

const (
	// RelayHTTPPort is the local HTTP port the relay server listens on.
	// cloudflared tunnels external WSS connections to this port.
	RelayHTTPPort = 8123

	// RelayUDPPort is the local UDP port used to bridge WireGuard traffic
	// on both the server (PC) and client (Mac) sides.
	RelayUDPPort = 51821

	maxPacketSize = 1500
)

// bridge runs a bidirectional UDP ↔ WebSocket relay.
// udpConn is bound to RelayUDPPort and bridges to wgAddr (WireGuard's listen port).
// ws provides ReadMessage / WriteMessage for the WebSocket side.
//
// bridge blocks until either side errors or closes.
type wsConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

func bridge(udpConn *net.UDPConn, wgAddr *net.UDPAddr, ws wsConn) {
	done := make(chan struct{})

	// UDP → WebSocket: WireGuard sends to relayPort, we forward to peer via WS.
	go func() {
		defer close(done)
		buf := make([]byte, maxPacketSize)
		for {
			n, _, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := ws.WriteMessage(2 /*BinaryMessage*/, buf[:n]); err != nil {
				return
			}
		}
	}()

	// WebSocket → UDP: peer sends WireGuard packet via WS, we inject into WireGuard.
	go func() {
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				udpConn.Close()
				return
			}
			// Sending to WireGuard's UDP port from our relay port causes WireGuard
			// to learn the peer's endpoint as 127.0.0.1:RelayUDPPort automatically.
			if _, err := udpConn.WriteTo(msg, wgAddr); err != nil {
				return
			}
		}
	}()

	<-done
}
