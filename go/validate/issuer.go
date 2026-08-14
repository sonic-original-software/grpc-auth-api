package validate

import "git.sonicoriginal.software/grpc-foundation/errors"

// Issuer validates an issuer string
func Issuer(issuer string) (violations []errors.FieldViolation) {
	if issuer == "" {
		violations = append(violations, errors.FieldViolation{
			Field:       "issuer",
			Description: "issuer is required",
		})
	}
	return
}
