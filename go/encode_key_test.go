//revive:disable:package-comments
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestEncodePrivateKey_PKCS1(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemData, err := EncodePrivateKey(privateKey, "PKCS1")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if !strings.Contains(pemData, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("expected PKCS1 PEM header")
	}
	if !strings.Contains(pemData, "-----END RSA PRIVATE KEY-----") {
		t.Error("expected PKCS1 PEM footer")
	}
}

func TestEncodePrivateKey_PKCS8(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pemData, err := EncodePrivateKey(privateKey, "PKCS8")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if !strings.Contains(pemData, "-----BEGIN PRIVATE KEY-----") {
		t.Error("expected PKCS8 PEM header")
	}
	if !strings.Contains(pemData, "-----END PRIVATE KEY-----") {
		t.Error("expected PKCS8 PEM footer")
	}
}

func TestEncodePrivateKey_UnsupportedFormat(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	_, err = EncodePrivateKey(privateKey, "UNKNOWN")
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' error, got '%v'", err)
	}
}

func TestEncodePrivateKey_UnsupportedKeyType(t *testing.T) {
	_, err := EncodePrivateKey("not a key", "PKCS1")
	if err == nil {
		t.Error("expected error for unsupported key type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected 'unsupported key type' error, got '%v'", err)
	}
}

func TestEncodePrivateKey_RoundTrip_PKCS1(t *testing.T) {
	originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode
	pemData, err := EncodePrivateKey(originalKey, "PKCS1")
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Parse back
	parsedKey, publicKey, signingMethod, err := ParsePrivateKey(pemData, "RS256")
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// Verify it's the same key by checking modulus
	parsedRSA, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}
	if originalKey.N.Cmp(parsedRSA.N) != 0 {
		t.Error("key modulus mismatch after round trip")
	}

	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod == nil {
		t.Error("expected non-nil signing method")
	}
}

func TestEncodePrivateKey_PKCS8_InvalidKey(t *testing.T) {
	// Create a malformed RSA key with nil fields
	invalidKey := &rsa.PrivateKey{}

	_, err := EncodePrivateKey(invalidKey, "PKCS8")
	if err == nil {
		t.Error("expected error for invalid RSA key, got nil")
	}
}

func TestEncodePrivateKey_RoundTrip_PKCS8(t *testing.T) {
	originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode
	pemData, err := EncodePrivateKey(originalKey, "PKCS8")
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Parse back
	parsedKey, publicKey, signingMethod, err := ParsePrivateKey(pemData, "RS256")
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// Verify it's the same key by checking modulus
	parsedRSA, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}
	if originalKey.N.Cmp(parsedRSA.N) != 0 {
		t.Error("key modulus mismatch after round trip")
	}

	if publicKey == nil {
		t.Error("expected non-nil public key")
	}
	if signingMethod == nil {
		t.Error("expected non-nil signing method")
	}
}
