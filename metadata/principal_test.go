//revive:disable:package-comments
package metadata

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestExtractPrincipal_Success(t *testing.T) {
	ctx := metadata.NewIncomingContext(
		t.Context(),
		metadata.Pairs(PrincipalIDKey, "principal-123"),
	)

	principalID, updatedCtx, err := ExtractPrincipal(ctx)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if principalID != "principal-123" {
		t.Errorf("expected 'principal-123', got '%s'", principalID)
	}

	if updatedCtx == nil {
		t.Fatal("expected updated context, got nil")
	}
}

func TestGetAuthenticatedPrincipal_NoMetadata(t *testing.T) {
	ctx := t.Context()

	_, updatedCtx, err := ExtractPrincipal(ctx)
	if updatedCtx == nil {
		t.Fatal("expected updated context even on error")
	}
	if err == nil {
		t.Fatal("expected error when no metadata, got nil")
	}
}

func TestGetAuthenticatedPrincipal_NoPrincipalID(t *testing.T) {
	ctx := metadata.NewIncomingContext(
		t.Context(),
		metadata.Pairs("other-key", "other-value"),
	)

	_, updatedCtx, err := ExtractPrincipal(ctx)
	if updatedCtx == nil {
		t.Fatal("expected updated context even on error")
	}
	if err == nil {
		t.Fatal("expected error when no principal ID, got nil")
	}
}

func TestGetAuthenticatedPrincipal_MultiplePrincipalIDs(t *testing.T) {
	md := metadata.Pairs(
		PrincipalIDKey, "principal-1",
		PrincipalIDKey, "principal-2",
	)
	ctx := metadata.NewIncomingContext(t.Context(), md)

	_, updatedCtx, err := ExtractPrincipal(ctx)
	if updatedCtx == nil {
		t.Fatal("expected updated context even on error")
	}
	if err == nil {
		t.Fatal("expected error for multiple principal IDs, got nil")
	}
}

func TestInjectPrincipalID(t *testing.T) {
	ctx := t.Context()

	ctx = InjectPrincipalID(ctx, "principal-789")

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected metadata in outgoing context")
	}

	values := md.Get(PrincipalIDKey)
	if len(values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(values))
	}

	if values[0] != "principal-789" {
		t.Errorf("expected 'principal-789', got '%s'", values[0])
	}
}
