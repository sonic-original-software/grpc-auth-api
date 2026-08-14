package validate

import "testing"

// Issuer validator is currently a stub that always returns violation
// These tests verify the current behavior
func TestIssuer_Success(t *testing.T) {
	violations := Issuer("test-issuer")
	if len(violations) != 0 {
		t.Errorf("expected no violations, got '%s'", violations)
	}

}

func TestIssuer_EmptyString(t *testing.T) {
	violations := Issuer("")
	if len(violations) == 0 {
		t.Error("expected violation, got none")
	}

	if violations[0].Field != "issuer" {
		t.Errorf("expected field 'issuer', got '%s'", violations[0].Field)
	}
}
