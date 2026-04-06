package agent

import (
	"log"
	"time"

	"github.com/FlashyFlash3011/tether/internal/api"
	"github.com/FlashyFlash3011/tether/internal/relay"
	"github.com/FlashyFlash3011/tether/internal/tunnel"
)

// peerState is the last-known set of peers, keyed by node_id.
type peerState map[string]api.PeerInfo

// PeerSyncer periodically fetches the peer list from the Worker and applies
// any changes (add/update/remove) to the WireGuard tunnel. It also re-registers
// this node on every sync tick to keep the KV entry alive (TTL = 5 min, sync = 30s).
type PeerSyncer struct {
	client     *api.Client
	tun        tunnel.Tunnel
	psk        string // base64 PSK shared with all peers
	interval   time.Duration
	current    peerState
	pubkey     string // this node's WireGuard public key (base64)
	listenPort int
	relayURL   string // this node's relay server URL (non-empty on PC)

	// relay client tracking (used on Mac/Darwin)
	activeRelayURL  string
	stopActiveRelay chan struct{}
}

func newPeerSyncer(client *api.Client, tun tunnel.Tunnel, psk string, interval time.Duration, pubkey string, listenPort int, relayURL string) *PeerSyncer {
	return &PeerSyncer{
		client:     client,
		tun:        tun,
		psk:        psk,
		interval:   interval,
		current:    make(peerState),
		pubkey:     pubkey,
		listenPort: listenPort,
		relayURL:   relayURL,
	}
}

// Run starts the sync loop. It blocks until stop is closed.
func (s *PeerSyncer) Run(stop <-chan struct{}) {
	// Sync immediately on startup, then on each tick.
	s.sync()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sync()
		case <-stop:
			if s.stopActiveRelay != nil {
				close(s.stopActiveRelay)
			}
			return
		}
	}
}

func (s *PeerSyncer) sync() {
	// Re-register on every tick to keep the KV entry alive (TTL = 5 min).
	if err := s.client.Register(s.pubkey, s.listenPort, s.relayURL); err != nil {
		log.Printf("sync: re-register: %v", err)
	}

	peers, err := s.client.GetPeers()
	if err != nil {
		log.Printf("sync: get peers: %v", err)
		return
	}

	next := make(peerState, len(peers))
	for _, p := range peers {
		next[p.NodeID] = p
	}

	// Add or update peers that are new or have changed.
	for id, p := range next {
		prev, exists := s.current[id]

		// Determine effective WireGuard endpoint.
		// If the peer has a relay URL, route through the local relay port
		// instead of the direct UDP endpoint.
		endpoint := p.Endpoint
		if p.RelayURL != "" {
			endpoint = relay.RelayEndpoint()
		}
		prevEndpoint := prev.Endpoint
		if prev.RelayURL != "" {
			prevEndpoint = relay.RelayEndpoint()
		}

		if !exists || prev.Pubkey != p.Pubkey || prevEndpoint != endpoint {
			if err := s.tun.SetPeer(p.Pubkey, p.VPNAddr, endpoint, s.psk); err != nil {
				log.Printf("sync: set peer %s: %v", id, err)
				continue
			}
			if !exists {
				log.Printf("sync: added peer %s (%s) endpoint=%s", id, p.VPNAddr, endpoint)
			} else {
				log.Printf("sync: updated peer %s endpoint → %s", id, endpoint)
			}
		}

		// Start or restart the relay client if the relay URL changed.
		// connectPeerRelay is a no-op on Linux (PC side).
		if p.RelayURL != "" && p.RelayURL != s.activeRelayURL {
			if s.stopActiveRelay != nil {
				close(s.stopActiveRelay)
			}
			stopCh := make(chan struct{})
			s.stopActiveRelay = stopCh
			s.activeRelayURL = p.RelayURL
			go connectPeerRelay(p.RelayURL, s.listenPort, stopCh)
			log.Printf("sync: relay client started → %s", p.RelayURL)
		}
	}

	// Remove peers that are no longer registered.
	for id, prev := range s.current {
		if _, ok := next[id]; !ok {
			if err := s.tun.RemovePeer(prev.Pubkey); err != nil {
				log.Printf("sync: remove peer %s: %v", id, err)
				continue
			}
			log.Printf("sync: removed peer %s", id)
			// Stop relay if this was the peer providing it.
			if prev.RelayURL != "" && prev.RelayURL == s.activeRelayURL {
				if s.stopActiveRelay != nil {
					close(s.stopActiveRelay)
					s.stopActiveRelay = nil
				}
				s.activeRelayURL = ""
			}
		}
	}

	s.current = next
}
