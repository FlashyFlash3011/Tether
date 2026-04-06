//go:build darwin

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

// DarwinTunnel manages a utun-backed WireGuard device on macOS.
// No root required — macOS grants utun device creation to any process.
type DarwinTunnel struct {
	dev      *device.Device
	ifName   string
}

// New returns the platform-specific Tunnel implementation.
func New() Tunnel {
	return &DarwinTunnel{}
}

func (t *DarwinTunnel) Name() string { return t.ifName }

func (t *DarwinTunnel) Up(privateKeyHex string, listenPort int, vpnCIDR string, mtu int) error {
	// "utun" lets macOS assign the next available utun number (utun0, utun1, …).
	tunDev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return fmt.Errorf("tunnel: create utun: %w", err)
	}
	t.ifName, err = tunDev.Name()
	if err != nil {
		return fmt.Errorf("tunnel: get utun name: %w", err)
	}

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

	// Parse our own VPN IP (strip the /32 CIDR suffix for ifconfig).
	myIP := strings.Split(vpnCIDR, "/")[0]

	// On macOS a point-to-point interface needs a "peer" address.
	// We use the peer's expected VPN IP as the destination.
	peerIP := peerVPNIP(myIP)

	cmds := [][]string{
		{"ifconfig", t.ifName, myIP, peerIP, "up"},
		{"ifconfig", t.ifName, "mtu", fmt.Sprintf("%d", mtu)},
		// Route the full 100.64.0.0/10 subnet through this interface.
		{"route", "-q", "-n", "add", "-net", "100.64.0.0/10", "-interface", t.ifName},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.dev.Close()
			return fmt.Errorf("tunnel: %v: %s: %w", args, out, err)
		}
	}
	return nil
}

func (t *DarwinTunnel) Down() error {
	if t.dev != nil {
		t.dev.Down()
		t.dev.Close()
	}
	if t.ifName != "" {
		exec.Command("route", "-q", "-n", "delete", "-net", "100.64.0.0/10").Run()
	}
	return nil
}

func (t *DarwinTunnel) SetPeer(pubkeyBase64, allowedIP, endpoint, pskBase64 string) error {
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
	return t.dev.IpcSet(ipc)
}

func (t *DarwinTunnel) RemovePeer(pubkeyBase64 string) error {
	pubkeyHex, err := b64ToHex(pubkeyBase64)
	if err != nil {
		return fmt.Errorf("tunnel: decode pubkey: %w", err)
	}
	return t.dev.IpcSet(buildPeerIPC(pubkeyHex, "", "", "", true))
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// peerVPNIP returns the expected peer IP for a given node's VPN IP.
// 100.64.0.1 ↔ 100.64.0.2 (the only two nodes in this setup).
func peerVPNIP(myIP string) string {
	switch myIP {
	case "100.64.0.1":
		return "100.64.0.2"
	case "100.64.0.2":
		return "100.64.0.1"
	default:
		return myIP
	}
}

func PickListenAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{Port: port}
}
