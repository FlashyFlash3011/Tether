package agent

import (
	"log"
	"time"

	"github.com/FlashyFlash3011/tether/internal/api"
	"github.com/FlashyFlash3011/tether/internal/tunnel"
)

// peerState is the last-known set of peers, keyed by node_id.
type peerState map[string]api.PeerInfo

// PeerSyncer periodically fetches the peer list from the Worker and applies
// any changes (add/update/remove) to the WireGuard tunnel.
type PeerSyncer struct {
	client   *api.Client
	tun      tunnel.Tunnel
	psk      string // base64 PSK shared with all peers
	interval time.Duration
	current  peerState
}

func newPeerSyncer(client *api.Client, tun tunnel.Tunnel, psk string, interval time.Duration) *PeerSyncer {
	return &PeerSyncer{
		client:   client,
		tun:      tun,
		psk:      psk,
		interval: interval,
		current:  make(peerState),
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
			return
		}
	}
}

func (s *PeerSyncer) sync() {
	peers, err := s.client.GetPeers()
	if err != nil {
		log.Printf("sync: get peers: %v", err)
		return
	}

	next := make(peerState, len(peers))
	for _, p := range peers {
		next[p.NodeID] = p
	}

	// Add or update peers that are new or have a changed endpoint/pubkey.
	for id, p := range next {
		prev, exists := s.current[id]
		if !exists || prev.Pubkey != p.Pubkey || prev.Endpoint != p.Endpoint {
			if err := s.tun.SetPeer(p.Pubkey, p.VPNAddr, p.Endpoint, s.psk); err != nil {
				log.Printf("sync: set peer %s: %v", id, err)
				continue
			}
			if !exists {
				log.Printf("sync: added peer %s (%s)", id, p.VPNAddr)
			} else {
				log.Printf("sync: updated peer %s endpoint → %s", id, p.Endpoint)
			}
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
		}
	}

	s.current = next
}
