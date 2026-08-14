//revive:disable:package-comments
package jwt_test

import (
	"time"

	libjwt "api/lib/jwt"
)

// CreateTestClaims creates test claims with sensible defaults.
// Subject is required, all other fields use default test values.
func CreateTestClaims(sub string) *libjwt.Claims {
	now := time.Now()
	return &libjwt.Claims{
		Sub: sub,
		Iss: "test-issuer",
		Aud: []string{"test-audience"},
		Exp: now.Add(1 * time.Hour).Unix(),
		Iat: now.Unix(),
		Jti: "test-token-id",
	}
}
