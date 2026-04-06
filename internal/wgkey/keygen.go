package wgkey

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Key is a 32-byte WireGuard key (private, public, or PSK).
type Key [32]byte

// GenerateKeypair returns a new private key and its corresponding public key.
func GenerateKeypair() (private Key, public Key, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Key{}, Key{}, fmt.Errorf("generate private key: %w", err)
	}
	pub := priv.PublicKey()
	copy(private[:], priv[:])
	copy(public[:], pub[:])
	return private, public, nil
}

// PublicFromPrivate derives the public key from a private key.
func PublicFromPrivate(private Key) Key {
	var wgPriv wgtypes.Key
	copy(wgPriv[:], private[:])
	pub := wgPriv.PublicKey()
	var out Key
	copy(out[:], pub[:])
	return out
}

// GeneratePreSharedKey returns a random 256-bit PSK.
func GeneratePreSharedKey() (Key, error) {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		return Key{}, fmt.Errorf("generate PSK: %w", err)
	}
	var out Key
	copy(out[:], k[:])
	return out, nil
}

// Base64 returns the standard base64 encoding of the key (WireGuard format).
func (k Key) Base64() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Hex returns the lowercase hex encoding of the key (WireGuard IPC format).
func (k Key) Hex() string {
	return hex.EncodeToString(k[:])
}

// String returns the base64 representation (safe to print — public keys are not secret).
func (k Key) String() string {
	return k.Base64()
}

// KeyFromBase64 parses a base64-encoded 32-byte key.
func KeyFromBase64(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("decode base64 key: %w", err)
	}
	if len(b) != 32 {
		return Key{}, fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	var k Key
	copy(k[:], b)
	return k, nil
}
