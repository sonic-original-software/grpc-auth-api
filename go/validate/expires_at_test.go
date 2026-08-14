package validate

import (
	"testing"
	"time"
)

func TestExpiresAt_Success(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Unix()

	violations := ExpiresAt(future)
	if len(violations) != 0 {
		t.Errorf("expected no violations for future expiry, got %d", len(violations))
	}
}

func TestExpiresAt_NoExpiry(t *testing.T) {
	violations := ExpiresAt(0)
	if len(violations) != 0 {
		t.Errorf("expected no violations for exp=0, got %d", len(violations))
	}
}

func TestExpiresAt_Past(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()

	violations := ExpiresAt(past)
	if len(violations) == 0 {
		t.Error("expected violation for past expiry, got none")
	}

	if violations[0].Field != "expires_at" {
		t.Errorf("expected field 'expires_at', got '%s'", violations[0].Field)
	}
}

func TestExpiresAt_Negative(t *testing.T) {
	violations := ExpiresAt(-1)
	if len(violations) == 0 {
		t.Error("expected violation for negative timestamp, got none")
	}
}
