package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the OS-appropriate directory for tether config files.
//
//	Linux:   ~/.config/tether
//	macOS:   ~/Library/Application Support/Tether
func ConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	var dir string
	switch runtime.GOOS {
	case "darwin":
		dir = filepath.Join(base, "Tether")
	default:
		dir = filepath.Join(base, "tether")
	}
	return dir, nil
}

// MkdirAllPrivate creates dir and all parents with mode 0700.
func MkdirAllPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir %s: %w", dir, err)
	}
	return nil
}
