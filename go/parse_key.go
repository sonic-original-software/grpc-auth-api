//revive:disable:package-comments
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ParsePrivateKey parses a PEM-encoded private key for the given algorithm.
// Returns private key, public key, signing method, and error.
// Supports RS256/RS384/RS512 (RSA keys).
// TODO: Add support for ES256/ES384/ES512 (ECDSA keys) when needed.
func ParsePrivateKey(
	pemData string, algorithm string,
) (privateKey any, publicKey any, signingMethod jwt.SigningMethod, err error) {
	switch algorithm {
	case "RS256":
		privKey, err := parseRSAPrivateKey(pemData)
		if err != nil {
			return nil, nil, nil, err
		}
		return privKey, &privKey.PublicKey, jwt.SigningMethodRS256, nil
	case "RS384":
		privKey, err := parseRSAPrivateKey(pemData)
		if err != nil {
			return nil, nil, nil, err
		}
		return privKey, &privKey.PublicKey, jwt.SigningMethodRS384, nil
	case "RS512":
		privKey, err := parseRSAPrivateKey(pemData)
		if err != nil {
			return nil, nil, nil, err
		}
		return privKey, &privKey.PublicKey, jwt.SigningMethodRS512, nil
	case "ES256", "ES384", "ES512":
		return nil, nil, nil, fmt.Errorf("ECDSA not yet supported")
	case "HS256", "HS384", "HS512":
		return nil, nil, nil, fmt.Errorf("HMAC not supported (use asymmetric keys)")
	default:
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// parseRSAPrivateKey parses an RSA private key from PEM format.
// Supports both PKCS1 and PKCS8 formats.
func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS1 format first
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}
	}

	return privateKey, nil
}
