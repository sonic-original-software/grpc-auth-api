package validate

import (
	"strings"
	"testing"
)

func TestSubject_Success(t *testing.T) {
	violations := Subject("valid-subject")
	if len(violations) != 0 {
		t.Errorf("expected no violations for valid subject, got %d", len(violations))
	}
}

func TestSubject_Empty(t *testing.T) {
	violations := Subject("")
	if len(violations) == 0 {
		t.Error("expected violation for empty subject, got none")
	}

	if violations[0].Field != "subject" {
		t.Errorf("expected field 'subject', got '%s'", violations[0].Field)
	}
}

func TestCreate_SubjectTooLong(t *testing.T) {
	violations := Subject(strings.Repeat("a", MaxSubjectLength+1))
	if len(violations) == 0 {
		t.Error("expected violation for subject too long, got none")
	}
}
