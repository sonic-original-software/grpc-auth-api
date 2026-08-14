//revive:disable:package-comments
package validate

import (
	"fmt"
	"strings"

	"git.sonicoriginal.software/grpc-foundation/errors"
)

const (
	maxAudienceLength = 253 // DNS hostname max length
)

// Audience validates an audience string array for JWT claims creation
func Audience(audience []string) (violations []errors.FieldViolation) {
	if len(audience) == 0 {
		violations = append(violations, errors.FieldViolation{
			Field:       "audience",
			Description: "audience is required",
		})
	} else {
		for i, aud := range audience {
			if aud == "" {
				violations = append(violations, errors.FieldViolation{
					Field:       fmt.Sprintf("audience[%d]", i),
					Description: "audience cannot be empty",
				})
			}
			if len(aud) > maxAudienceLength {
				violations = append(violations, errors.FieldViolation{
					Field:       fmt.Sprintf("audience[%d]", i),
					Description: fmt.Sprintf("exceeds maximum length of %d characters", maxAudienceLength),
				})
			}
			// Validate audience format (should be hostname-like or service identifier)
			if strings.ContainsAny(aud, "\n\r\t\x00") {
				violations = append(violations, errors.FieldViolation{
					Field:       fmt.Sprintf("audience[%d]", i),
					Description: "contains invalid characters",
				})
			}
		}
	}
	return
}
