package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/FlashyFlash3011/tether/internal/agent"
	"github.com/FlashyFlash3011/tether/internal/config"
	"github.com/FlashyFlash3011/tether/internal/keystore"
	"github.com/FlashyFlash3011/tether/internal/wgkey"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdDown()
	case "keygen":
		err = cmdKeygen()
	case "pskgen":
		err = cmdPskgen()
	case "keystore":
		err = cmdKeystore(args)
	case "setup":
		err = cmdSetup()
	case "version":
		fmt.Printf("tether %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ── up ────────────────────────────────────────────────────────────────────────

func cmdUp(args []string) error {
	cfgPath, err := defaultConfigPath()
	if err != nil {
		return err
	}
	if len(args) > 0 {
		cfgPath = args[0]
	}
	return agent.Run(cfgPath)
}

// ── down ──────────────────────────────────────────────────────────────────────

func cmdDown() error {
	pidPath, err := pidFilePath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("tether is not running (no PID file at %s)", pidPath)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return fmt.Errorf("invalid PID in %s", pidPath)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("send signal to %d: %w", pid, err)
	}
	fmt.Printf("sent SIGINT to tether (pid %d)\n", pid)
	return nil
}

// ── keygen ────────────────────────────────────────────────────────────────────

func cmdKeygen() error {
	priv, pub, err := wgkey.GenerateKeypair()
	if err != nil {
		return err
	}

	cfgDir, err := config.ConfigDir()
	if err != nil {
		return err
	}
	if err := config.MkdirAllPrivate(cfgDir); err != nil {
		return err
	}
	ks, err := keystore.New(cfgDir)
	if err != nil {
		return err
	}
	if err := ks.Set(keystore.KeyPrivate, []byte(priv.Base64())); err != nil {
		return fmt.Errorf("store private key: %w", err)
	}

	fmt.Printf("Public key (add to coordination Worker config):\n%s\n", pub.Base64())
	return nil
}

// ── pskgen ────────────────────────────────────────────────────────────────────

func cmdPskgen() error {
	psk, err := wgkey.GeneratePreSharedKey()
	if err != nil {
		return err
	}
	fmt.Printf("PSK (store on both nodes with: tether keystore set wg-psk <value>):\n%s\n", psk.Base64())
	return nil
}

// ── keystore ──────────────────────────────────────────────────────────────────

func cmdKeystore(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: tether keystore set <key> <value>")
	}
	if args[0] != "set" {
		return fmt.Errorf("usage: tether keystore set <key> <value>")
	}
	if len(args) < 3 {
		return fmt.Errorf("usage: tether keystore set <key> <value>")
	}
	key := args[1]
	value := args[2]

	// Validate value is valid base64 (all keystore values are base64-encoded secrets).
	if _, err := base64.StdEncoding.DecodeString(value); err != nil {
		return fmt.Errorf("value must be base64-encoded (got %q): %w", value, err)
	}

	cfgDir, err := config.ConfigDir()
	if err != nil {
		return err
	}
	if err := config.MkdirAllPrivate(cfgDir); err != nil {
		return err
	}
	ks, err := keystore.New(cfgDir)
	if err != nil {
		return err
	}
	if err := ks.Set(key, []byte(value)); err != nil {
		return fmt.Errorf("keystore set %s: %w", key, err)
	}
	fmt.Printf("stored %s in keystore\n", key)
	return nil
}

// ── setup ─────────────────────────────────────────────────────────────────────

func cmdSetup() error {
	switch runtime.GOOS {
	case "linux":
		bin, err := os.Executable()
		if err != nil {
			bin = "/usr/local/bin/tether"
		}
		fmt.Printf("Run the following command once to grant tether NET_ADMIN capability:\n\n")
		fmt.Printf("  sudo setcap cap_net_admin+ep %s\n\n", bin)
		fmt.Printf("This allows tether to create the tether0 TUN interface without running as root.\n")
	case "darwin":
		fmt.Printf("No setup required on macOS — utun devices are available without root.\n")
	default:
		fmt.Printf("Platform %s: manual setup may be required.\n", runtime.GOOS)
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func defaultConfigPath() (string, error) {
	dir, err := config.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

func pidFilePath() (string, error) {
	// Use XDG_RUNTIME_DIR if available (Linux systemd), fall back to /tmp.
	runDir := os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		runDir = os.TempDir()
	}
	return filepath.Join(runDir, "tether.pid"), nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `tether — personal VPN agent

Usage:
  tether up [config.toml]     Start VPN daemon (default: ~/.config/tether/config.toml)
  tether down                 Stop running daemon
  tether keygen               Generate WireGuard keypair, store in keystore, print public key
  tether pskgen               Generate a WireGuard pre-shared key (copy to both nodes)
  tether keystore set <k> <v> Store a secret in the keystore (value must be base64)
  tether setup                Print platform-specific setup instructions
  tether version              Print version

Keystore keys:
  wg-private-key   WireGuard private key (set by: tether keygen)
  api-token        HMAC secret for Worker auth (from: wrangler secret put TOKEN_*)
  wg-psk           WireGuard pre-shared key (set by: tether pskgen then keystore set)
`)
}
