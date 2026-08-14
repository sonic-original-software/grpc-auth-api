//revive:disable:package-comments
package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Decode a JWT's signature and return the claims
func Decode(
	tokenString string, publicKey any, validMethods []string,
) (*Claims, error) {
	protoClaims := &Claims{}

	_, err := jwt.ParseWithClaims(
		tokenString,
		protoClaims,
		func(_ *jwt.Token) (any, error) {
			return publicKey, nil
		},
		jwt.WithValidMethods(validMethods),
		jwt.WithLeeway(5*time.Second),
	)

	if err != nil {
		// Invalid signature, expired, or validation failed
		return nil, err
	}

	return protoClaims, nil
}
