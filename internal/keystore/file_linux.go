//go:build linux

package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/term"
)

const (
	saltLen     = 16
	pbkdf2Iters = 600_000
	keyLen      = 32
	nonceLen    = 24
)

// FileStore is an encrypted-file keystore for Linux/WSL2.
// Each key is stored as a separate file under dir.
// Files are encrypted with NaCl secretbox using a key derived from a passphrase.
type FileStore struct {
	dir        string
	passphrase []byte
}

// NewFileStore creates a FileStore rooted at dir.
// The passphrase is read from the TETHER_KEYSTORE_PASSPHRASE environment variable;
// if absent, the user is prompted interactively (requires a terminal).
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

// Set encrypts value and writes it to disk (mode 0600).
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
	// File layout: salt (16) || nonce+ciphertext
	out := append(salt, encrypted...)

	p := s.path(key)
	if err := os.WriteFile(p, out, 0600); err != nil {
		return fmt.Errorf("keystore: write %s: %w", p, err)
	}
	return nil
}

// Get decrypts and returns the value for key.
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
		return nil, fmt.Errorf("keystore: %s is corrupt (too short)", key)
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
		return nil, fmt.Errorf("keystore: decryption failed for %s (wrong passphrase?)", key)
	}
	return plaintext, nil
}

// Delete removes the encrypted file for key.
func (s *FileStore) Delete(key string) error {
	err := os.Remove(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// New returns the default keystore for this platform.
func New(dir string) (Store, error) {
	return NewFileStore(dir)
}
