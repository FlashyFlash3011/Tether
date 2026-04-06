// Package tunnel manages the WireGuard VPN interface and peer configuration.
package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

// Tunnel manages a WireGuard interface lifecycle.
type Tunnel interface {
	// Up brings the WireGuard interface up with the given private key.
	Up(privateKeyHex string, listenPort int, vpnCIDR string, mtu int) error
	// Down tears down the interface.
	Down() error
	// SetPeer adds or updates a peer.
	SetPeer(pubkeyBase64, allowedIP, endpoint, pskBase64 string) error
	// RemovePeer removes a peer by public key.
	RemovePeer(pubkeyBase64 string) error
	// UpdateEndpoint changes only the endpoint for an existing peer.
	UpdateEndpoint(pubkeyBase64, endpoint string) error
	// LastHandshake returns the Unix timestamp of the most recent WireGuard
	// handshake for the given peer, or 0 if no handshake has occurred.
	LastHandshake(pubkeyBase64 string) (int64, error)
	// Name returns the OS interface name (e.g. "tether0", "utun3").
	Name() string
}

// ── Shared helpers used by both platform implementations ─────────────────────

// keyToHex converts a base64-encoded WireGuard key to lowercase hex.
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode base64 key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// lastHandshakeFromDevice returns the latest_handshake Unix timestamp for a
// peer from the WireGuard IPC output.
func lastHandshakeFromDevice(dev *device.Device, pubkeyBase64 string) (int64, error) {
	pubkeyHex, err := keyToHex(pubkeyBase64)
	if err != nil {
		return 0, err
	}
	ipcOut, err := dev.IpcGet()
	if err != nil {
		return 0, fmt.Errorf("ipc get: %w", err)
	}
	inPeer := false
	for _, line := range strings.Split(ipcOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public_key=") {
			inPeer = strings.TrimPrefix(line, "public_key=") == pubkeyHex
			continue
		}
		if inPeer && strings.HasPrefix(line, "latest_handshake=") {
			var ts int64
			fmt.Sscanf(strings.TrimPrefix(line, "latest_handshake="), "%d", &ts)
			return ts, nil
		}
	}
	return 0, nil
}

// updateEndpointOnDevice updates only the endpoint for an existing peer via IPC.
func updateEndpointOnDevice(dev *device.Device, pubkeyBase64, endpoint string) error {
	pubkeyHex, err := keyToHex(pubkeyBase64)
	if err != nil {
		return err
	}
	return dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", pubkeyHex, endpoint))
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
	// Keepalive every 25s keeps NAT mappings alive and beats the Cloudflare
	// Workers WebSocket 100s idle timeout on the relay path.
	sb.WriteString("persistent_keepalive_interval=25\n")
	return sb.String()
}
