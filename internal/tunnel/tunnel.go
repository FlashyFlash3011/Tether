// Package tunnel manages the WireGuard VPN interface and peer configuration.
package tunnel

import (
	"fmt"
	"strings"
)

// Tunnel manages a WireGuard interface lifecycle.
type Tunnel interface {
	// Up brings the WireGuard interface up with the given private key.
	Up(privateKeyHex string, listenPort int, vpnCIDR string, mtu int) error
	// Down tears down the interface.
	Down() error
	// SetPeer adds or updates a peer. Empty endpoint leaves it unchanged.
	SetPeer(pubkeyBase64, allowedIP, endpoint, pskBase64 string) error
	// RemovePeer removes a peer by public key.
	RemovePeer(pubkeyBase64 string) error
	// Name returns the OS interface name (e.g. "tether0", "utun3").
	Name() string
}

// buildPeerIPC returns the WireGuard IPC protocol fragment for a single peer.
// See https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation
func buildPeerIPC(pubkeyHex, allowedIP, endpointStr, pskHex string, remove bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "public_key=%s\n", pubkeyHex)
	if remove {
		sb.WriteString("remove=true\n")
		return sb.String()
	}
	if pskHex != "" {
		fmt.Fprintf(&sb, "preshared_key=%s\n", pskHex)
	}
	if endpointStr != "" {
		fmt.Fprintf(&sb, "endpoint=%s\n", endpointStr)
	}
	fmt.Fprintf(&sb, "allowed_ip=%s\n", allowedIP)
	// Keepalive every 25s — keeps NAT mappings alive and beats the Cloudflare
	// Workers WebSocket 100s idle timeout (if relay path is in use).
	sb.WriteString("persistent_keepalive_interval=25\n")
	return sb.String()
}
