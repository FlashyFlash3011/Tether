//go:build darwin && cgo

package keystore

import (
	"fmt"

	"github.com/99designs/keyring"
)

const keychainService = "tether"

// KeychainStore uses the macOS Keychain (native build only).
type KeychainStore struct {
	ring keyring.Keyring
}

// NewKeychainStore opens the macOS Keychain for the tether service.
func NewKeychainStore() (*KeychainStore, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName:              keychainService,
		AllowedBackends:          []keyring.BackendType{keyring.KeychainBackend},
		KeychainName:             "login",
		KeychainTrustApplication: true,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore: open keychain: %w", err)
	}
	return &KeychainStore{ring: ring}, nil
}

func (s *KeychainStore) Set(key string, value []byte) error {
	err := s.ring.Set(keyring.Item{
		Key:  key,
		Data: value,
	})
	if err != nil {
		return fmt.Errorf("keystore: keychain set %s: %w", key, err)
	}
	return nil
}

func (s *KeychainStore) Get(key string) ([]byte, error) {
	item, err := s.ring.Get(key)
	if err == keyring.ErrKeyNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: keychain get %s: %w", key, err)
	}
	return item.Data, nil
}

func (s *KeychainStore) Delete(key string) error {
	err := s.ring.Remove(key)
	if err == keyring.ErrKeyNotFound {
		return nil
	}
	return err
}

// New returns a Keychain-backed store on macOS native builds.
func New(dir string) (Store, error) {
	return NewKeychainStore()
}
