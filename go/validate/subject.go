package validate

import (
	"fmt"

	"git.sonicoriginal.software/grpc-foundation/errors"
)

const (
	// MaxSubjectLength for a JWT Subject claim
	MaxSubjectLength = 256
)

// Subject validates a subject for jwt claims creation
func Subject(subject string) (violations []errors.FieldViolation) {
	if subject == "" {
		violations = append(violations, errors.FieldViolation{
			Field:       "subject",
			Description: "subject is required",
		})
	} else if len(subject) > MaxSubjectLength {
		violations = append(violations, errors.FieldViolation{
			Field:       "subject",
			Description: fmt.Sprintf("subject exceeds maximum length of %d characters", MaxSubjectLength),
		})
	}
	return
}
