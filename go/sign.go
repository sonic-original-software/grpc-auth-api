//revive:disable:package-comments
package jwt

import (
	"context"

	"git.sonicoriginal.software/grpc-foundation/errors"
	"github.com/golang-jwt/jwt/v5"
)

// Sign claims into a JWT
func Sign(
	ctx context.Context,
	claims jwt.Claims,
	privateKey any,
	signingMethod jwt.SigningMethod,
) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", errors.Internal(ctx, "failed to sign token", "SIGNING_FAILED", "token")
	}
	return tokenString, nil
}
