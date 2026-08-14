//revive:disable:package-comments
package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	libjwt "api/lib/jwt"
)

func TestSign_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	testClaims := CreateTestClaims("test-user-sign")

	tokenString, err := libjwt.Sign(
		t.Context(), testClaims, privateKey, jwt.SigningMethodRS256,
	)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if tokenString == "" {
		t.Fatal("expected non-empty token string")
	}

	// Verify using jwt library directly (not our Decode function)
	parsedClaims := &libjwt.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, parsedClaims,
		func(token *jwt.Token) (any, error) {
			return publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
	)

	if err != nil {
		t.Fatalf("jwt library failed to parse signed token: %v", err)
	}

	if !token.Valid {
		t.Error("token should be valid")
	}

	if parsedClaims.Sub != "test-user-sign" {
		t.Errorf("expected sub 'test-user-sign', got '%s'", parsedClaims.Sub)
	}
}

func TestSign_WithoutExpiry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	testClaims := CreateTestClaims("test-user")
	testClaims.Exp = 0 // Never expires

	tokenString, err := libjwt.Sign(
		t.Context(), testClaims, privateKey, jwt.SigningMethodRS256,
	)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	// Verify token is valid and has no expiry
	parsedClaims := &libjwt.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, parsedClaims,
		func(token *jwt.Token) (any, error) {
			return publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
	)

	if err != nil {
		t.Fatalf("jwt library failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("non-expiring token should be valid")
	}

	if parsedClaims.Exp != 0 {
		t.Errorf("expected exp 0, got %d", parsedClaims.Exp)
	}
}

func TestSign_AllClaimsPreserved(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	testClaims := CreateTestClaims("test-user")

	tokenString, err := libjwt.Sign(
		t.Context(), testClaims, privateKey, jwt.SigningMethodRS256,
	)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	parsedClaims := &libjwt.Claims{}
	_, err = jwt.ParseWithClaims(tokenString, parsedClaims,
		func(token *jwt.Token) (any, error) {
			return publicKey, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
	)

	if err != nil {
		t.Fatalf("jwt library failed to parse: %v", err)
	}

	// Verify all claims are preserved through signing
	if parsedClaims.Sub != testClaims.Sub {
		t.Errorf("sub mismatch: expected '%s', got '%s'", testClaims.Sub, parsedClaims.Sub)
	}
	if parsedClaims.Iss != testClaims.Iss {
		t.Errorf("iss mismatch: expected '%s', got '%s'", testClaims.Iss, parsedClaims.Iss)
	}
	if len(parsedClaims.Aud) != len(testClaims.Aud) {
		t.Errorf("aud length mismatch: expected %d, got %d", len(testClaims.Aud), len(parsedClaims.Aud))
	}
	if parsedClaims.Jti != testClaims.Jti {
		t.Errorf("jti mismatch: expected '%s', got '%s'", testClaims.Jti, parsedClaims.Jti)
	}
	if parsedClaims.Iat != testClaims.Iat {
		t.Errorf("iat mismatch: expected %d, got %d", testClaims.Iat, parsedClaims.Iat)
	}
}

func TestSign_NilKey(t *testing.T) {
	testClaims := CreateTestClaims("test-user")

	_, err := libjwt.Sign(
		t.Context(), testClaims, nil, jwt.SigningMethodRS256,
	)
	if err == nil {
		t.Fatal("expected error for nil key, got nil")
	}
}

func TestSign_InvalidKeyType(t *testing.T) {
	testClaims := CreateTestClaims("test-user")

	// Pass wrong key type (string instead of rsa.PrivateKey)
	_, err := libjwt.Sign(
		t.Context(), testClaims, "not-a-key", jwt.SigningMethodRS256,
	)
	if err == nil {
		t.Fatal("expected error for invalid key type, got nil")
	}
}
