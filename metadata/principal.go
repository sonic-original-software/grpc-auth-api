//revive:disable:package-comments
package metadata

import (
	"context"
	"fmt"

	"google.golang.org/grpc/metadata"

	"git.sonicoriginal.software/logger"
)

const (
	// PrincipalIDKey is the gRPC metadata key for the authenticated principal ID.
	// The "sub" claim from validated JWT can be extracted and injected into this metadata field.
	// Services read this field to identify the authenticated principal.
	PrincipalIDKey = "x-principal-id"
)

// ExtractPrincipal extracts the authenticated principal ID from gRPC metadata.
// Updates logger with authentication status and stores in context.
// Returns: principal ID, updated context (with enriched logger), error.
// If authenticated: logger has "requester" and "authenticated=true"
// If not authenticated: logger has "authenticated=false"
func ExtractPrincipal(
	ctx context.Context,
) (
	principalID string, updatedCtx context.Context, err error,
) {
	log := logger.FromContext(ctx)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log = log.With("authenticated", false)
		ctx = logger.ContextWithLogger(ctx, log)
		return "", ctx, fmt.Errorf("no metadata in request")
	}

	values := md.Get(PrincipalIDKey)

	if len(values) == 0 {
		log = log.With("authenticated", false)
		ctx = logger.ContextWithLogger(ctx, log)
		return "", ctx, fmt.Errorf("no principal ID in metadata")
	}

	if len(values) > 1 {
		log = log.With("authenticated", false)
		ctx = logger.ContextWithLogger(ctx, log)
		return "", ctx, fmt.Errorf("multiple principal IDs in metadata")
	}

	// Success - add requester and authenticated flag to logger
	log = log.With("requester", values[0], "authenticated", true)
	ctx = logger.ContextWithLogger(ctx, log)
	return values[0], ctx, nil
}

// InjectPrincipalID injects the authenticated principal ID into outgoing gRPC metadata.
// Used by gateway to propagate authenticated principal to backend services.
func InjectPrincipalID(ctx context.Context, principalID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, PrincipalIDKey, principalID)
}
