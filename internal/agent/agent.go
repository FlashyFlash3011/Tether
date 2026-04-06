// Package agent is the main VPN node daemon. It loads configuration and
// secrets, brings up the WireGuard tunnel, registers with the coordination
// Worker, and keeps peers in sync until the process receives SIGTERM/SIGINT.
package agent

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FlashyFlash3011/tether/internal/api"
	"github.com/FlashyFlash3011/tether/internal/config"
	"github.com/FlashyFlash3011/tether/internal/keystore"
	"github.com/FlashyFlash3011/tether/internal/tunnel"
	"github.com/FlashyFlash3011/tether/internal/wgkey"
)

// Run is the entry point for `tether up`. It blocks until shutdown.
func Run(cfgPath string) error {
	// ── Load config ──────────────────────────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	log.Printf("tether: starting node=%s vpn=%s", cfg.Node.ID, cfg.Node.VPNIP)

	// ── Open keystore ────────────────────────────────────────────────────────
	cfgDir, err := config.ConfigDir()
	if err != nil {
		return fmt.Errorf("agent: config dir: %w", err)
	}
	ks, err := keystore.New(cfgDir)
	if err != nil {
		return fmt.Errorf("agent: keystore: %w", err)
	}

	// ── Load secrets from keystore ───────────────────────────────────────────
	privKeyB64, err := loadSecret(ks, keystore.KeyPrivate)
	if err != nil {
		return fmt.Errorf("agent: private key not found — run `tether keygen` first: %w", err)
	}
	apiTokenB64, err := loadSecret(ks, keystore.KeyAPIToken)
	if err != nil {
		return fmt.Errorf("agent: api token not found — run `tether keystore set api-token <value>`: %w", err)
	}
	pskB64, err := loadSecret(ks, keystore.KeyPSK)
	if err != nil {
		// PSK is optional; log a warning but continue.
		log.Printf("tether: warning: PSK not set (run `tether pskgen` for post-quantum protection)")
		pskB64 = ""
	}

	// Decode private key to get the public key.
	privKey, err := wgkey.KeyFromBase64(privKeyB64)
	if err != nil {
		return fmt.Errorf("agent: decode private key: %w", err)
	}
	pubKey := wgkey.PublicFromPrivate(privKey)

	// ── Bring up WireGuard tunnel ─────────────────────────────────────────────
	tun := tunnel.New()
	privKeyHex := privKey.Hex()
	if err := tun.Up(privKeyHex, cfg.WireGuard.ListenPort, cfg.Node.VPNIP, cfg.Node.MTU); err != nil {
		return fmt.Errorf("agent: tunnel up: %w", err)
	}
	log.Printf("tether: interface %s up (vpn=%s)", tun.Name(), cfg.Node.VPNIP)

	defer func() {
		log.Printf("tether: shutting down")
		tun.Down()
	}()

	// ── Start relay server (PC/Linux only; no-op on Mac/Darwin) ──────────────
	relayURL, stopRelay, err := startRelayServer(cfg.WireGuard.ListenPort)
	if err != nil {
		log.Printf("tether: warning: relay server failed to start: %v", err)
		relayURL = ""
		stopRelay = func() {}
	} else if relayURL != "" {
		log.Printf("tether: relay server up at %s", relayURL)
		defer stopRelay()
	}

	// ── Register with coordination Worker ─────────────────────────────────────
	apiToken, err := base64.StdEncoding.DecodeString(apiTokenB64)
	if err != nil {
		return fmt.Errorf("agent: decode api token: %w", err)
	}
	apiClient := api.New(cfg.Server.URL, cfg.Node.ID, apiToken)

	if err := apiClient.Register(pubKey.Base64(), cfg.WireGuard.ListenPort, relayURL); err != nil {
		return fmt.Errorf("agent: register: %w", err)
	}
	log.Printf("tether: registered with %s", cfg.Server.URL)

	// ── Start peer sync loop ──────────────────────────────────────────────────
	syncInterval, err := time.ParseDuration(cfg.Sync.Interval)
	if err != nil {
		syncInterval = 30 * time.Second
	}
	syncer := newPeerSyncer(apiClient, tun, pskB64, syncInterval, pubKey.Base64(), cfg.WireGuard.ListenPort, relayURL)
	stop := make(chan struct{})
	go syncer.Run(stop)

	// ── Wait for shutdown signal ──────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	close(stop)
	return nil
}

// loadSecret retrieves a base64-encoded secret from the keystore.
// Trims whitespace so copy-paste with trailing newlines doesn't break base64 decoding.
func loadSecret(ks keystore.Store, key string) (string, error) {
	raw, err := ks.Get(key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// StoreSecret is called by CLI subcommands that write to the keystore.
func StoreSecret(ks keystore.Store, key, valueB64 string) error {
	return ks.Set(key, []byte(valueB64))
}
