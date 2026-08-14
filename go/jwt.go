//revive:disable:package-comments
package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GetIssuer implements jwt.Claims.GetIssuer
func (c *Claims) GetIssuer() (string, error) {
	return c.Iss, nil
}

// GetAudience implements jwt.Claims.GetAudience
func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Aud, nil
}

// GetSubject implements jwt.Claims.GetSubject
func (c *Claims) GetSubject() (string, error) {
	return c.Sub, nil
}

// GetExpirationTime implements jwt.Claims.GetExpirationTime
// Returns nil if Exp is 0 (never expires)
func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Exp == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Exp, 0)), nil
}

// GetIssuedAt implements jwt.Claims.GetIssuedAt
func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.Iat, 0)), nil
}

// GetNotBefore implements jwt.Claims.GetNotBefore
// Returns nil if Nbf is 0 (not set)
func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.Nbf == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Nbf, 0)), nil
}
