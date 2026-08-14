//revive:disable:package-comments
package jwt

import (
	"context"
	"time"

	"github.com/google/uuid"

	"api/lib/jwt/validate"

	"git.sonicoriginal.software/grpc-foundation/errors"
)

func validateCreateRequest(
	subject string, audience []string, expiresAt, notBefore int64,
) []errors.FieldViolation {
	// Calculate exact capacity: subject(1) + expires_at(1) + audience(1 or 3*len)
	// Worst case: 3 + len(audience)*3 violations
	maxViolations := 3 + len(audience)*3
	violations := make([]errors.FieldViolation, 0, maxViolations)
	violations = append(violations, validate.Subject(subject)...)
	violations = append(violations, validate.Audience(audience)...)
	violations = append(violations, validate.ExpiresAt(expiresAt)...)
	violations = append(violations, validate.NotBefore(notBefore)...)
	return violations
}

// Create a jwt and return the Claims
func Create(
	ctx context.Context,
	id, issuer, subject string,
	audience []string,
	expiresAt, notBefore int64,
) (*Claims, error) {
	violations := validateCreateRequest(subject, audience, expiresAt, notBefore)
	if len(violations) > 0 {
		return nil, errors.InvalidArgument(ctx, "validation failed", violations...)
	}

	// Use provided ID or generate UUID if not provided
	if id == "" {
		id = uuid.New().String()
	}

	// Create claims
	return &Claims{
		Sub: subject,
		Aud: audience,
		Iss: issuer,
		Exp: expiresAt,
		Iat: time.Now().Unix(),
		Nbf: notBefore,
		Jti: id,
	}, nil
}
