package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Node holds per-machine configuration (non-secret).
type Node struct {
	ID    string `toml:"id"`    // "pc" or "mac"
	VPNIP string `toml:"vpn_ip"` // e.g. "100.64.0.1/32"
	MTU   int    `toml:"mtu"`
}

// Server holds the coordination Worker URL.
type Server struct {
	URL string `toml:"url"` // e.g. "https://tether-coord.X.workers.dev"
}

// WireGuard holds WireGuard-specific settings.
type WireGuard struct {
	ListenPort int `toml:"listen_port"` // default 51820
}

// Sync holds peer-sync tuning.
type Sync struct {
	Interval string `toml:"interval"` // Go duration string, e.g. "30s"
}

// Config is the full node configuration loaded from config.toml.
// Secrets (private key, API token, PSK) are stored in the keystore, not here.
type Config struct {
	Node      Node      `toml:"node"`
	Server    Server    `toml:"server"`
	WireGuard WireGuard `toml:"wg"`
	Sync      Sync      `toml:"sync"`
}

// Load reads config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes cfg to path with mode 0600.
func Save(cfg *Config, path string) error {
	if err := MkdirAllPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

// Validate returns an error if required fields are missing.
func (c *Config) Validate() error {
	if c.Node.ID == "" {
		return fmt.Errorf("config: node.id is required (\"pc\" or \"mac\")")
	}
	if c.Node.ID != "pc" && c.Node.ID != "mac" {
		return fmt.Errorf("config: node.id must be \"pc\" or \"mac\", got %q", c.Node.ID)
	}
	if c.Node.VPNIP == "" {
		return fmt.Errorf("config: node.vpn_ip is required")
	}
	if c.Server.URL == "" {
		return fmt.Errorf("config: server.url is required")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Node.MTU == 0 {
		c.Node.MTU = 1420
	}
	if c.WireGuard.ListenPort == 0 {
		c.WireGuard.ListenPort = 51820
	}
	if c.Sync.Interval == "" {
		c.Sync.Interval = "30s"
	}
}
