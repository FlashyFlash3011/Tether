//go:build linux

package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const ifaceName = "tether0"

// LinuxTunnel manages a kernel TUN-backed WireGuard device on Linux/WSL2.
// Requires cap_net_admin on the binary:
//
//	sudo setcap cap_net_admin+ep /usr/local/bin/tether
//
// All network configuration is done via netlink (in-process), so no
// child processes are spawned and cap_net_admin is used directly.
type LinuxTunnel struct {
	dev  *device.Device
	name string
}

// New returns the platform-specific Tunnel implementation.
func New() Tunnel {
	return &LinuxTunnel{}
}

func (t *LinuxTunnel) Name() string { return t.name }

func (t *LinuxTunnel) Up(privateKeyHex string, listenPort int, vpnCIDR string, mtu int) error {
	// Create the kernel TUN device.
	tunDev, err := tun.CreateTUN(ifaceName, mtu)
	if err != nil {
		return fmt.Errorf("tunnel: create TUN %s: %w (hint: run `tether setup` for required setcap command)", ifaceName, err)
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

	// Configure the interface via netlink (runs in-process, uses cap_net_admin).
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: find interface %s: %w", ifaceName, err)
	}

	addr, err := netlink.ParseAddr(vpnCIDR)
	if err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: parse VPN CIDR %s: %w", vpnCIDR, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: assign VPN IP: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		t.dev.Close()
		return fmt.Errorf("tunnel: bring link up: %w", err)
	}

	return nil
}

func (t *LinuxTunnel) Down() error {
	if t.dev != nil {
		t.dev.Down()
		t.dev.Close()
	}
	// Best-effort cleanup.
	if link, err := netlink.LinkByName(ifaceName); err == nil {
		netlink.LinkDel(link)
	}
	return nil
}

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

	ipc := buildPeerIPC(pubkeyHex, allowedIP, endpoint, pskHex, false)
	if err := t.dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("tunnel: set peer: %w", err)
	}

	// Add a host route for the peer's VPN IP via this interface.
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("tunnel: find interface: %w", err)
	}
	_, dst, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return fmt.Errorf("tunnel: parse peer CIDR %s: %w", allowedIP, err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
	}
	// RouteReplace = add if not exists, update if exists.
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("tunnel: add route %s: %w", allowedIP, err)
	}
	return nil
}

func (t *LinuxTunnel) RemovePeer(pubkeyBase64 string) error {
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

func PickListenAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{Port: port}
}
