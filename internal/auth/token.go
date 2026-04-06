// Package auth handles HMAC-HS256 JWT creation and validation for node
// authentication against the Cloudflare Worker coordination server.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenTTL = 5 * time.Minute

type claims struct {
	NodeID string `json:"node_id"`
	jwt.RegisteredClaims
}

// NewToken creates a signed JWT for nodeID using secret.
// The token expires in 5 minutes.
func NewToken(nodeID string, secret []byte) (string, error) {
	now := time.Now()
	c := claims{
		NodeID: nodeID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign token: %w", err)
	}
	return signed, nil
}

// ValidateToken parses tokenStr and verifies it against the per-node secret
// found in allowedNodes (nodeID → secret). Returns the nodeID on success.
//
// allowedNodes must contain exactly the known node IDs; any other node_id claim
// is rejected even with a valid signature.
func ValidateToken(tokenStr string, allowedNodes map[string][]byte) (string, error) {
	// First pass: parse without verification to extract node_id.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenStr, &claims{})
	if err != nil {
		return "", fmt.Errorf("auth: parse token: %w", err)
	}
	c, ok := unverified.Claims.(*claims)
	if !ok || c.NodeID == "" {
		return "", fmt.Errorf("auth: missing node_id claim")
	}

	secret, allowed := allowedNodes[c.NodeID]
	if !allowed {
		return "", fmt.Errorf("auth: unknown node_id %q", c.NodeID)
	}

	// Second pass: verify signature with the correct secret.
	verified, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("auth: verify token: %w", err)
	}
	if !verified.Valid {
		return "", fmt.Errorf("auth: token invalid")
	}

	vc, ok := verified.Claims.(*claims)
	if !ok {
		return "", fmt.Errorf("auth: claims type assertion failed")
	}
	return vc.NodeID, nil
}
