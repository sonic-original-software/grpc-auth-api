//revive:disable:package-comments
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncodePrivateKey encodes a private key to PEM format.
// Supports RSA keys in either PKCS1 or PKCS8 format.
func EncodePrivateKey(privateKey any, format string) (string, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return encodeRSAPrivateKey(key, format)
	default:
		return "", fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// encodeRSAPrivateKey encodes an RSA private key to PEM format.
// Supports "PKCS1" and "PKCS8" formats.
func encodeRSAPrivateKey(privateKey *rsa.PrivateKey, format string) (string, error) {
	switch format {
	case "PKCS1":
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		return string(privateKeyPEM), nil
	case "PKCS8":
		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return "", fmt.Errorf("failed to marshal PKCS8 private key: %w", err)
		}
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		return string(privateKeyPEM), nil
	default:
		return "", fmt.Errorf("unsupported format: %s (use PKCS1 or PKCS8)", format)
	}
}
