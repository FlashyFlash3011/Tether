//go:build darwin && !cgo

// file_darwin.go is the fallback used when cross-compiling for macOS from Linux
// (CGO disabled, so the Keychain backend is unavailable). Uses the same
// encrypted-file approach as the Linux backend.

package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	saltLen     = 16
	pbkdf2Iters = 600_000
	keyLen      = 32
	nonceLen    = 24
)

type FileStore struct {
	dir        string
	passphrase []byte
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("keystore: create dir %s: %w", dir, err)
	}
	pass, err := resolvePassphrase()
	if err != nil {
		return nil, err
	}
	return &FileStore{dir: dir, passphrase: pass}, nil
}

func resolvePassphrase() ([]byte, error) {
	if v := os.Getenv("TETHER_KEYSTORE_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("keystore: TETHER_KEYSTORE_PASSPHRASE not set and no terminal available")
	}
	fmt.Fprint(os.Stderr, "Keystore passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("keystore: read passphrase: %w", err)
	}
	return pass, nil
}

func (s *FileStore) path(key string) string {
	return filepath.Join(s.dir, key+".enc")
}

func (s *FileStore) Set(key string, value []byte) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("keystore: generate salt: %w", err)
	}
	dk := pbkdf2.Key(s.passphrase, salt, pbkdf2Iters, keyLen, sha256.New)
	var boxKey [keyLen]byte
	copy(boxKey[:], dk)
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("keystore: generate nonce: %w", err)
	}
	encrypted := secretbox.Seal(nonce[:], value, &nonce, &boxKey)
	out := append(salt, encrypted...)
	p := s.path(key)
	if err := os.WriteFile(p, out, 0600); err != nil {
		return fmt.Errorf("keystore: write %s: %w", p, err)
	}
	return nil
}

func (s *FileStore) Get(key string) ([]byte, error) {
	p := s.path(key)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keystore: read %s: %w", p, err)
	}
	if len(data) < saltLen+nonceLen+secretbox.Overhead {
		return nil, fmt.Errorf("keystore: %s is corrupt", key)
	}
	salt := data[:saltLen]
	rest := data[saltLen:]
	dk := pbkdf2.Key(s.passphrase, salt, pbkdf2Iters, keyLen, sha256.New)
	var boxKey [keyLen]byte
	copy(boxKey[:], dk)
	var nonce [nonceLen]byte
	copy(nonce[:], rest[:nonceLen])
	plaintext, ok := secretbox.Open(nil, rest[nonceLen:], &nonce, &boxKey)
	if !ok {
		return nil, fmt.Errorf("keystore: decryption failed for %s", key)
	}
	return plaintext, nil
}

func (s *FileStore) Delete(key string) error {
	err := os.Remove(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func New(dir string) (Store, error) {
	return NewFileStore(dir)
}
