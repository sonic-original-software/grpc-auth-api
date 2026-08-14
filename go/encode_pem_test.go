//revive:disable:package-comments
package jwt_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// EncodePEMPrivateKey encodes an RSA private key to PEM format (PKCS1)
func EncodePEMPrivateKey(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

// EncodePEMPrivateKeyPKCS8 encodes an RSA private key to PEM format (PKCS8)
func EncodePEMPrivateKeyPKCS8(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM), nil
}
