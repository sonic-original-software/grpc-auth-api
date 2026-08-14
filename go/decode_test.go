//revive:disable:package-comments
package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	libjwt "api/lib/jwt"
)

func TestDecode_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	testClaims := CreateTestClaims("test-user-123")
	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	decodedClaims, err := libjwt.Decode(tokenString, publicKey, []string{"RS256"})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if decodedClaims.Sub != "test-user-123" {
		t.Errorf("expected sub 'test-user-123', got '%s'", decodedClaims.Sub)
	}

	if decodedClaims.Iss != "test-issuer" {
		t.Errorf("expected iss 'test-issuer', got '%s'", decodedClaims.Iss)
	}
}

func TestDecode_ExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	testClaims := CreateTestClaims("test-user")
	testClaims.Exp = time.Now().Add(-1 * time.Hour).Unix() // Expired

	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	_, err = libjwt.Decode(tokenString, publicKey, []string{"RS256"})
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestDecode_InvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate different RSA key: %v", err)
	}
	differentPublicKey := &differentKey.PublicKey

	testClaims := CreateTestClaims("test-user")
	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	_, err = libjwt.Decode(tokenString, differentPublicKey, []string{"RS256"})
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
}

func TestDecode_WrongAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	testClaims := CreateTestClaims("test-user")
	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	// Token is RS256 but we only allow RS384
	_, err = libjwt.Decode(tokenString, publicKey, []string{"RS384"})
	if err == nil {
		t.Fatal("expected error for algorithm mismatch, got nil")
	}
}

func TestDecode_MalformedToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	_, err = libjwt.Decode("not.a.valid.jwt", publicKey, []string{"RS256"})
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

func TestDecode_EmptyToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	_, err = libjwt.Decode("", publicKey, []string{"RS256"})
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestDecode_TokenWithoutExpiry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	testClaims := CreateTestClaims("test-user")
	testClaims.Exp = 0 // No expiry

	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	decodedClaims, err := libjwt.Decode(tokenString, publicKey, []string{"RS256"})
	if err != nil {
		t.Fatalf("expected success for non-expiring token, got error: %v", err)
	}

	if decodedClaims.Exp != 0 {
		t.Errorf("expected exp 0, got %d", decodedClaims.Exp)
	}
}

func TestDecode_NotYetValid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	testClaims := CreateTestClaims("test-user")
	testClaims.Nbf = time.Now().Add(1 * time.Hour).Unix() // Not valid for 1 hour

	tokenString := CreateTestJWT(t, jwt.SigningMethodRS256, privateKey, testClaims)

	_, err = libjwt.Decode(tokenString, publicKey, []string{"RS256"})
	if err == nil {
		t.Fatal("expected error for not-yet-valid token, got nil")
	}
}
