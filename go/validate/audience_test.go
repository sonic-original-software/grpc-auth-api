package validate

import (
	"strings"
	"testing"
)

func TestAudience_Success(t *testing.T) {
	violations := Audience([]string{"api", "storage"})
	if len(violations) != 0 {
		t.Errorf("expected no violations for valid audience, got %d", len(violations))
	}
}

func TestAudience_Empty(t *testing.T) {
	violations := Audience([]string{})
	if len(violations) == 0 {
		t.Error("expected violation for empty audience, got none")
	}
}

func TestCreate_AudienceWithEmptyString(t *testing.T) {
	violations := Audience([]string{"api.example.com", "", "storage.example.com"})
	if len(violations) == 0 {
		t.Error("expected violation for empty string in audience, got none")
	}
}

func TestCreate_AudienceTooLong(t *testing.T) {
	violations := Audience([]string{strings.Repeat("a", maxAudienceLength+1)})
	if len(violations) == 0 {
		t.Error("expected violation for audience too long, got none")
	}
}

func TestCreate_AudienceWithInvalidCharacters(t *testing.T) {
	testCases := []struct {
		name     string
		audience string
	}{
		{"newline", "api.example.com\nmalicious"},
		{"carriage return", "api.example.com\rmalicious"},
		{"tab", "api.example.com\tmalicious"},
		{"null byte", "api.example.com\x00malicious"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_ *testing.T) {
			_ = Audience([]string{tc.audience})
		})
	}
}
