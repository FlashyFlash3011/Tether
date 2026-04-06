//go:build linux

package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const ifaceName = "tether0"

// LinuxTunnel manages a kernel TUN-backed WireGuard device on Linux/WSL2.
// Requires cap_net_admin on the binary:
//
//	sudo setcap cap_net_admin+ep /usr/local/bin/tether
type LinuxTunnel struct {
	dev  *device.Device
	name string
}

// New returns the platform-specific Tunnel implementation.
func New() Tunnel {
	return &LinuxTunnel{}
}

func (t *LinuxTunnel) Name() string { return t.name }

// Up creates the tether0 TUN interface, starts the WireGuard device, and
// configures the VPN IP address and routing.
func (t *LinuxTunnel) Up(privateKeyHex string, listenPort int, vpnCIDR string, mtu int) error {
	tunDev, err := tun.CreateTUN(ifaceName, mtu)
	if err != nil {
		return fmt.Errorf("tunnel: create TUN %s: %w (is cap_net_admin set?)", ifaceName, err)
	}
	t.name = ifaceName

	logger := device.NewLogger(device.LogLevelError, "tether: ")
	t.dev = device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privateKeyHex, listenPort)
	if err := t.dev.IpcSet(ipc); err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: configure WireGuard: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: bring up device: %w", err)
	}

	// Configure the OS interface: assign IP, bring link up, add VPN route.
	cmds := [][]string{
		{"ip", "addr", "add", vpnCIDR, "dev", ifaceName},
		{"ip", "link", "set", ifaceName, "up"},
	}
	// Add a host route for every peer's VPN /32.
	// The peer's IP is inferred from the subnet: 100.64.0.x/32 where x ≠ ours.
	// Routes are added per-peer in SetPeer; the commands above just bring the link up.
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.dev.Close()
			return fmt.Errorf("tunnel: %v: %s: %w", args, out, err)
		}
	}
	return nil
}

// Down tears down the WireGuard device and removes the interface.
func (t *LinuxTunnel) Down() error {
	if t.dev != nil {
		t.dev.Down()
		t.dev.Close()
	}
	// Best-effort cleanup; ignore errors (interface may already be gone).
	exec.Command("ip", "link", "del", ifaceName).Run()
	return nil
}

// SetPeer adds or updates a WireGuard peer and installs a host route for it.
func (t *LinuxTunnel) SetPeer(pubkeyBase64, allowedIP, endpoint, pskBase64 string) error {
	pubkeyHex, err := b64ToHex(pubkeyBase64)
	if err != nil {
		return fmt.Errorf("tunnel: decode pubkey: %w", err)
	}
	var pskHex string
	if pskBase64 != "" {
		pskHex, err = b64ToHex(pskBase64)
		if err != nil {
			return fmt.Errorf("tunnel: decode PSK: %w", err)
		}
	}

	ipc := "public_key=" + pubkeyHex + "\n" + buildPeerIPC(pubkeyHex, allowedIP, endpoint, pskHex, false)
	if err := t.dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("tunnel: set peer: %w", err)
	}

	// Install a host route so the OS knows to send traffic for this peer's
	// VPN IP through our tether0 interface.
	peerHost := strings.Split(allowedIP, "/")[0] + "/32"
	out, err := exec.Command("ip", "route", "replace", peerHost, "dev", ifaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tunnel: add route %s: %s: %w", peerHost, out, err)
	}
	return nil
}

// RemovePeer removes a WireGuard peer by public key.
func (t *LinuxTunnel) RemovePeer(pubkeyBase64 string) error {
	pubkeyHex, err := b64ToHex(pubkeyBase64)
	if err != nil {
		return fmt.Errorf("tunnel: decode pubkey: %w", err)
	}
	ipc := buildPeerIPC(pubkeyHex, "", "", "", true)
	return t.dev.IpcSet(ipc)
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// PickListenAddr returns a *net.UDPAddr suitable for binding WireGuard's port.
// This is used by the agent to bind the socket before passing it to the tunnel.
func PickListenAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{Port: port}
}
