//go:build linux

package agent

import (
	"fmt"

	"github.com/FlashyFlash3011/tether/internal/cloudflared"
	"github.com/FlashyFlash3011/tether/internal/relay"
)

// startRelayServer starts the local UDP↔WebSocket relay server and a
// cloudflared quick tunnel to expose it publicly. The returned URL is the
// https://*.trycloudflare.com address that the Mac connects to.
// stop must be called on shutdown.
func startRelayServer(wgListenPort int) (relayURL string, stop func(), err error) {
	srv := relay.NewServer(wgListenPort)
	srv.Start()

	url, stopCF, err := cloudflared.Start(relay.RelayHTTPPort)
	if err != nil {
		srv.Stop()
		return "", func() {}, fmt.Errorf("cloudflared: %w", err)
	}

	return url, func() { stopCF(); srv.Stop() }, nil
}

// connectPeerRelay is a no-op on Linux — the PC is the relay server, not client.
func connectPeerRelay(_ string, _ int, _ <-chan struct{}) {}
