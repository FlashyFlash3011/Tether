// Package keystore provides secure storage for secrets (WireGuard private key,
// API token, PSK). On macOS (native build) it uses the Keychain; on Linux it
// uses an encrypted file under ~/.config/tether/.
package keystore

import "fmt"

// Well-known key names stored in the keystore.
const (
	KeyPrivate  = "wg-private-key" // WireGuard private key (32 bytes, base64)
	KeyAPIToken = "api-token"       // HMAC secret for Worker JWT auth (32 bytes, base64)
	KeyPSK      = "wg-psk"          // WireGuard pre-shared key (32 bytes, base64)
)

// Store is the interface for reading and writing secrets.
type Store interface {
	// Set stores value under key, replacing any existing value.
	Set(key string, value []byte) error
	// Get retrieves the value for key. Returns ErrNotFound if absent.
	Get(key string) ([]byte, error)
	// Delete removes key. No-op if absent.
	Delete(key string) error
}

// ErrNotFound is returned by Get when the key does not exist.
var ErrNotFound = fmt.Errorf("keystore: key not found")
