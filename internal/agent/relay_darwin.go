//go:build darwin

package agent

import (
	"log"
	"time"

	"github.com/FlashyFlash3011/tether/internal/relay"
)

// startRelayServer is a no-op on macOS — the Mac is the relay client.
func startRelayServer(_ int) (string, func(), error) {
	return "", func() {}, nil
}

// connectPeerRelay dials wsURL (the cloudflared relay) and bridges WireGuard
// packets through it. It reconnects automatically on connection drops.
// Blocks until stop is closed — run in a goroutine.
func connectPeerRelay(wsURL string, wgListenPort int, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		client := relay.NewClient(wgListenPort)
		if err := client.Connect(wsURL); err != nil {
			log.Printf("relay: disconnected (%v), reconnecting in 5s", err)
		}
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
		}
	}
}
