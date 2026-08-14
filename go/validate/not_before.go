package validate

import (
	"git.sonicoriginal.software/grpc-foundation/errors"
)

// NotBefore validates a not-before timestamp.
// Only checks that the timestamp is non-negative.
// Actual validation of whether token has activated happens during Decode.
func NotBefore(notBefore int64) (violations []errors.FieldViolation) {
	if notBefore < 0 {
		violations = append(violations, errors.FieldViolation{
			Field:       "not_before",
			Description: "not_before cannot be negative",
		})
	}
	return
}
