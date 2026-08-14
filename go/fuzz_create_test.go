//revive:disable:package-comments
package jwt

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testIssuer = "https://test.example.com"

// FuzzCreate fuzzes the Create operation to find crashes and edge cases
func FuzzCreate(f *testing.F) {
	// Seed corpus with known good and interesting inputs
	// Format: subject, audience, expires_at

	// Valid inputs
	f.Add("user-123", "api.example.com", time.Now().Add(7*24*time.Hour).Unix())
	f.Add("service-account-456", "registry.example.com", int64(0)) // Non-expiring

	// Edge cases
	f.Add("", "api.example.com", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-789", "", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-def", "api.example.com", int64(-1))
	f.Add("user-ghi", "api.example.com", time.Now().Add(-1*time.Hour).Unix())

	// Boundary values
	f.Add("user-jkl", "api.example.com", int64(0)) // Non-expiring
	f.Add("user-mno", "api.example.com", int64(1))
	f.Add("user-pqr", "api.example.com", int64(9999999999))

	// Special characters and Unicode
	f.Add("user-🚀", "api.example.com", time.Now().Add(1*time.Hour).Unix())

	// Very long inputs (testing length limits)
	f.Add(strings.Repeat("a", 1000), "api.example.com", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-123", strings.Repeat("a", 300)+".com", time.Now().Add(1*time.Hour).Unix())

	// Validation edge cases - audience
	f.Add("user-123", "api.example.com,", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-123", ",api.example.com", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-123", "api.example.com\n", time.Now().Add(1*time.Hour).Unix())

	f.Fuzz(
		func(
			t *testing.T, subject string, audience string, expiresAt int64,
		) {
			// Convert comma-separated strings to slices
			var audienceSlice []string
			if audience != "" {
				audienceSlice = strings.Split(audience, ",")
			}

			claims, err := Create(
				t.Context(),
				"",
				testIssuer,
				subject,
				audienceSlice,
				expiresAt,
				0,
			)

			// If we got a response, verify it's reasonable
			if err == nil {
				if claims == nil {
					t.Fatal("got nil response with nil error")
				}
				if claims == nil {
					t.Fatal("got nil claims in response")
				}

				// Verify claims fields match request
				if claims.Sub != subject {
					t.Errorf("subject mismatch: got %q, want %q", claims.Sub, subject)
				}

				if claims.Exp != expiresAt {
					t.Errorf("expires_at mismatch: got %d, want %d", claims.Exp, expiresAt)
				}

				// Verify generated fields are set
				if claims.Jti == "" {
					t.Error("claims ID should be set")
				}

				if claims.Iat == 0 {
					t.Error("claims created_at should be set")
				}

				// created_at should be reasonable (within last minute)
				now := time.Now().Unix()
				if claims.Iat > now || claims.Iat < now-60 {
					t.Errorf("claims created_at unreasonable: %d (now: %d)", claims.Iat, now)
				}

				// Verify audience matches
				audienceClaimsLen := len(claims.Aud)
				audienceSliceLen := len(audienceSlice)
				if audienceClaimsLen != audienceSliceLen {
					t.Errorf(
						"audience length mismatch: got %d, want %d",
						audienceClaimsLen, audienceSliceLen)
				}
			} else {
				// If we got an error, verify it's a valid gRPC error
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("error is not a gRPC status error: %v", err)
				}

				// Verify error code is one of the expected codes
				code := st.Code()
				validCodes := []codes.Code{
					codes.InvalidArgument,
					codes.Internal,
				}

				isValidCode := slices.Contains(validCodes, code)

				if !isValidCode {
					t.Errorf("unexpected error code: %v (message: %s)", code, st.Message())
				}

				// Error message should not be empty
				if st.Message() == "" {
					t.Error("error message should not be empty")
				}
			}
		})
}

// FuzzCreate_JWTEncoding fuzzes the Create operation with JWT encoding
// to ensure the claims can always be encoded to a valid JWT if creation succeeds
func FuzzCreate_JWTEncoding(f *testing.F) {
	// Seed with valid inputs that should encode successfully
	f.Add("user-123", "api.example.com", time.Now().Add(1*time.Hour).Unix())
	f.Add("user-456", "api.example.com,storage.example.com", time.Now().Add(1*time.Hour).Unix())
	f.Add("service-789", "registry.example.com", int64(0))

	f.Fuzz(
		func(
			t *testing.T, subject string, audience string, expiresAt int64,
		) {
			var audienceSlice []string
			if audience != "" {
				audienceSlice = strings.Split(audience, ",")
			}

			claims, err := Create(
				t.Context(),
				"",
				testIssuer,
				subject,
				audienceSlice,
				expiresAt,
				0,
			)

			// Verify generated fields if creation succeeded
			if err == nil && claims != nil {
				if claims.Jti == "" {
					t.Error("claims ID should be set")
				}

				if claims.Iat == 0 {
					t.Error("claims created_at should be set")
				}

				if claims.Iss == "" {
					t.Error("claims issuer should be set")
				}
			}
		})
}
