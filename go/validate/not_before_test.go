package validate

import (
	"testing"
	"time"
)

func TestNotBefore_Success(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Unix()

	violations := NotBefore(future)
	if len(violations) != 0 {
		t.Errorf("expected no violations for future timestamp, got %d", len(violations))
	}
}

func TestNotBefore_CurrentTime(t *testing.T) {
	now := time.Now().Unix()

	violations := NotBefore(now)
	if len(violations) != 0 {
		t.Errorf("expected no violations for current time, got %d", len(violations))
	}
}

func TestNotBefore_Past(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()

	violations := NotBefore(past)
	if len(violations) != 0 {
		t.Errorf("expected no violations for past timestamp, got %d", len(violations))
	}
}

func TestNotBefore_Zero(t *testing.T) {
	violations := NotBefore(0)
	if len(violations) != 0 {
		t.Errorf("expected no violations for nbf=0, got %d", len(violations))
	}
}

func TestNotBefore_Negative(t *testing.T) {
	violations := NotBefore(-1)
	if len(violations) == 0 {
		t.Error("expected violation for negative timestamp, got none")
	}

	if violations[0].Field != "not_before" {
		t.Errorf("expected field 'not_before', got '%s'", violations[0].Field)
	}
}
