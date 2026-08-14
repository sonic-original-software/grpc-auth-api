package validate

import (
	"time"

	"git.sonicoriginal.software/grpc-foundation/errors"
)

// ExpiresAt validates an expiry timestamp for JWT claims creation
func ExpiresAt(expiresAt int64) (violations []errors.FieldViolation) {
	if expiresAt < 0 {
		violations = append(violations, errors.FieldViolation{
			Field:       "expires_at",
			Description: "expires_at must be >= 0 (0 for non-expiring)",
		})
	} else if expiresAt > 0 && expiresAt <= time.Now().Unix() {
		violations = append(violations, errors.FieldViolation{
			Field:       "expires_at",
			Description: "expires_at must be in the future",
		})
	}
	return
}
