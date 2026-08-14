//revive:disable:package-comments
package jwt_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	libjwt "api/lib/jwt"
)

// CreateTestJWT creates a signed JWT with the given signing method and claims.
// Supports any algorithm - caller specifies the signing method and appropriate key type.
func CreateTestJWT(
	t *testing.T,
	signingMethod jwt.SigningMethod,
	privateKey any,
	testClaims *libjwt.Claims,
) string {
	t.Helper()
	token := jwt.NewWithClaims(signingMethod, testClaims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}
	return tokenString
}

func TestCreate_Success(t *testing.T) {
	now := time.Now()

	claims, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		"test-subject",
		[]string{"test-audience"},
		now.Add(1*time.Hour).Unix(),
		now.Unix(),
	)

	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if claims.Jti != "test-id" {
		t.Errorf("expected jti 'test-id', got '%s'", claims.Jti)
	}
	if claims.Iss != "test-issuer" {
		t.Errorf("expected iss 'test-issuer', got '%s'", claims.Iss)
	}
	if claims.Sub != "test-subject" {
		t.Errorf("expected sub 'test-subject', got '%s'", claims.Sub)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "test-audience" {
		t.Errorf("expected aud ['test-audience'], got %v", claims.Aud)
	}
}

func TestCreate_AutoGenerateJTI(t *testing.T) {
	now := time.Now()

	claims, err := libjwt.Create(
		t.Context(),
		"", // Empty ID - should auto-generate
		"test-issuer",
		"test-subject",
		[]string{"test-audience"},
		now.Add(1*time.Hour).Unix(),
		now.Unix(),
	)

	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if claims.Jti == "" {
		t.Error("expected auto-generated jti, got empty")
	}

	// JTI should be a UUID format
	if len(claims.Jti) != 36 {
		t.Errorf("expected UUID length 36, got %d", len(claims.Jti))
	}
}

func TestCreate_EmptySubject(t *testing.T) {
	now := time.Now()

	_, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		"", // Empty subject
		[]string{"test-audience"},
		now.Add(1*time.Hour).Unix(),
		now.Unix(),
	)

	if err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
}

func TestCreate_SubjectTooLong(t *testing.T) {
	now := time.Now()
	longSubject := string(make([]byte, 300)) // Exceeds 256 char limit

	_, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		longSubject,
		[]string{"test-audience"},
		now.Add(1*time.Hour).Unix(),
		now.Unix(),
	)

	if err == nil {
		t.Fatal("expected error for subject too long, got nil")
	}
}

func TestCreate_EmptyAudience(t *testing.T) {
	now := time.Now()

	_, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		"test-subject",
		[]string{}, // Empty audience
		now.Add(1*time.Hour).Unix(),
		now.Unix(),
	)

	if err == nil {
		t.Fatal("expected error for empty audience, got nil")
	}
}

func TestCreate_ExpirationInPast(t *testing.T) {
	now := time.Now()

	_, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		"test-subject",
		[]string{"test-audience"},
		now.Add(-1*time.Hour).Unix(), // Past expiration
		now.Unix(),
	)

	if err == nil {
		t.Fatal("expected error for expiration in past, got nil")
	}
}

func TestCreate_NoExpiration(t *testing.T) {
	now := time.Now()

	claims, err := libjwt.Create(
		t.Context(),
		"test-id",
		"test-issuer",
		"test-subject",
		[]string{"test-audience"},
		0, // No expiration
		now.Unix(),
	)

	if err != nil {
		t.Fatalf("expected success for non-expiring token, got error: %v", err)
	}

	if claims.Exp != 0 {
		t.Errorf("expected exp 0, got %d", claims.Exp)
	}
}
