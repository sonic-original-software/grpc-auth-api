# Authentication System

## Overview

The authentication system validates principal credentials via WebAuthn
(passkeys, biometrics, security keys) and orchestrates the creation of JWT
claims. It acts as the entry point for authentication flows and maintains the
mapping between WebAuthn credentials and internal principal IDs.

## Architecture

The authentication system provides passwordless authentication through
**WebAuthnService** - FIDO2-compliant authentication using passkeys, biometrics,
and security keys.

## Identity Verification Flow

### Registration Flow (Two-Phase)

**Phase 1: BeginRegistration**

1. Client sends `BeginRegistrationRequest` (optionally includes `name` and
   `display_name`)
2. Authentication service creates a new principal via Principal service
   (generates unique principal ID)
3. Constructs WebAuthn user entity:
   - `user.id` - **Always** the server-generated principal ID (never
     client-provided)
   - `user.name` - Optional client-provided value (empty string if not provided)
   - `user.displayName` - Optional client-provided value (empty string if not
     provided)
4. Generates WebAuthn challenge via go-webauthn library
5. Creates stateless session token (JWT) via Token service containing:
   - Challenge (in `claims.id`)
   - Principal ID (in `claims.subject`)
   - 5-minute expiry
6. Returns credential creation options (JSON) + session token to client

**Phase 2: FinishRegistration**

1. Client sends `FinishRegistrationRequest` with:
   - Credential data from authenticator (attestation object, client data JSON,
     credential ID)
   - Session token from BeginRegistration
2. Authentication service decodes session token to retrieve challenge and
   principal ID
3. Validates WebAuthn credential via go-webauthn library (cryptographic
   verification)
4. Stores credential mapping (credential ID → principal ID) in database
5. Creates access token (JWT) via Token service with 24-hour expiry
6. Returns JWT claims to client

### Login Flow (Two-Phase)

**Phase 1: BeginLogin**

1. Client sends `BeginLoginRequest`
2. Authentication service generates WebAuthn challenge
3. Creates stateless session token (JWT) containing challenge
4. Returns credential request options (JSON) + session token to client

**Phase 2: FinishLogin**

1. Client sends `FinishLoginRequest` with:
   - Assertion data from authenticator (signature)
   - Session token from BeginLogin
2. Authentication service decodes session token to retrieve challenge
3. Validates assertion signature against stored public key
4. Looks up credential ID → principal ID mapping
5. Updates sign counter (replay attack prevention)
6. Creates access token (JWT) via Token service
7. Returns JWT claims to client

**Key principles**:

- Authentication service issues JWTs directly via the Token service
- No API Gateway required for authentication flows
- Principal IDs are server-generated, never client-provided
- WebAuthn ceremonies use stateless session tokens (short-lived JWTs)

## WebAuthn Credential Mapping

WebAuthn uses cryptographic credentials (biometrics, security keys).

**Mapping Strategy**:

- Each WebAuthn credential has unique cryptographic identifier
- Authentication service maps credential identifiers to internal principals
- Supports multiple credentials per principal (multiple devices/authenticators)
- Credential mapping enables passwordless authentication

**Credential Storage**:

The authentication service stores comprehensive credential information per the
W3C WebAuthn specification:

**Required Fields**:

- `credential_id` - Unique identifier for the credential
- `public_key` - Public key for signature verification
- `sign_count` - Counter for replay attack detection (MUST be updated on each
  use)

**Attestation Fields** (for security policies and auditing):

- `attestation_type` - Type of attestation (e.g., "packed", "fido-u2f", "none")
- `aaguid` - Authenticator Attestation GUID (identifies authenticator model)
- `attestation.object` - CBOR-encoded attestation data from registration
- `attestation.client_data_json` - Client data from registration ceremony

**Transport & Capability Fields** (for UX and policy decisions):

- `transport` - How authenticator communicates (USB, NFC, BLE, internal, hybrid)
- `flags.user_present` - User presence was verified (UP flag)
- `flags.user_verified` - User was biometrically verified (UV flag)
- `flags.backup_eligible` - Credential can be backed up/synced
- `flags.backup_state` - Credential is currently backed up (e.g., via
  iCloud/Google)

**Management Fields**:

- `name` - Human-readable name (e.g., "YubiKey 5", "iPhone 15 Pro")
- `created_at` - When credential was registered
- `last_used_at` - Last successful authentication timestamp
- `authenticator.clone_warning` - Set if possible cloned authenticator detected
- `authenticator.attachment` - Platform (built-in) or cross-platform (roaming)

**Use Cases for Extended Credential Data**:

1. **Security Policies**: Enforce "only FIDO2-certified authenticators" or
   "require user verification"
2. **User Experience**: Show users which credentials are synced ("This passkey
   syncs via iCloud")
3. **Clone Detection**: Detect compromised authenticators via sign counter
   irregularities
4. **Audit & Compliance**: Track authenticator types, usage patterns,
   attestation chains
5. **Recovery UX**: Help users identify credentials ("Your YubiKey, last used 3
   days ago")

### Principal Classification via Authentication

Authentication mappings enable **emergent classification** of principals:

**Principals with authentication mappings**:

- Can log in interactively via WebAuthn
- Have one or more registered credentials (passkeys, security keys, biometrics)
- Identified by presence in credential mapping system

**Principals without authentication mappings**:

- Cannot log in interactively
- May use API keys for programmatic access
- Typically service accounts or system principals

This enables **usage-based billing**: charge per principal that can
authenticate, not for non-authenticating principals.

## WebAuthn Operations

The WebAuthnService provides the following operations:

### Registration

Register a new passkey for first-time account creation:

1. Client initiates registration
2. Authentication service generates WebAuthn challenge
3. Authenticator (device) creates new credential
4. Authentication service validates credential
5. Store credential → principal mapping
6. Create principal in Principal service
7. Return JWT claims for immediate sign-in

### Authentication

Authenticate with existing passkey:

1. Client initiates authentication
2. Authentication service generates WebAuthn challenge
3. Authenticator signs challenge with private key
4. Authentication service validates signature with stored public key
5. Look up credential → principal mapping
6. Create new JWT claims
7. Return JWT claims for API access

### Credential Management

- **Add Credential** - Register additional passkeys to an existing account
- **List Credentials** - View all registered passkeys for the authenticated
  principal
- **Delete Credential** - Remove a passkey (e.g., lost device)

## Response Structure

The authentication service returns `Claims` proto messages containing:

- `subject` - Principal ID
- `issuer` - Token issuer (from TOKEN_ISSUER environment variable)
- `audience` - Intended recipients (e.g., \["api"\])
- `expires_at` - Unix timestamp when token expires (default: 24 hours)
- `created_at` - Unix timestamp when token was created
- `id` - Unique token identifier (jti)

**Client receives** JWT access tokens with 24-hour expiry (configurable via
environment)

## Logout

**There is no server-side logout operation.** Logout is entirely a client-side
action where the client deletes their access token from local storage.

**Important security consideration**: Deleted tokens remain cryptographically
valid until their expiry time. If an attacker obtained a copy of the token
before deletion, they can still use it until expiry. This is an accepted
tradeoff of stateless authentication.

**Mitigation**: Access token TTL (default: 24 hours, configurable) balances
security and UX. See the API Gateway documentation for client integration best
practices including proactive re-authentication prompts.

## Re-authentication

When a principal's access token expires:

1. Client makes API request with expired token
2. API Gateway returns 401 Unauthenticated error
3. Client redirects principal to WebAuthn authentication flow
4. Principal re-authenticates (biometric prompt or security key)
5. Authentication service validates credential and looks up principal ID
6. Authentication service creates new JWT claims with same principal ID
7. Client receives new access token (default: 24 hours, configurable)

**Identity Continuity**: WebAuthn credentials are permanently mapped to
principal IDs. Re-authenticating with the same passkey always returns the same
principal ID, maintaining consistent identity across sessions.

**Proactive Re-authentication UX**:

Clients should prompt users to renew credentials before expiry:

```javascript
// Check token expiry
if (timeUntilExpiry < 24hours) {
  showBanner("Session expires soon. Renew now?");
}
```

WebAuthn re-authentication is typically instant (one biometric verification or
security key touch).

## Integration

**Authentication service calls**:

- **Principal service** - Create new principals during registration
- **Token service** - Create and sign JWT tokens (both session tokens and access
  tokens)

**Called by**:

- Web/frontend applications, mobile apps, CLI tools (direct gRPC calls)
- Backend services

## Security Considerations

**WebAuthn Security**:

- Cryptographic challenge-response prevents replay attacks
- Public key cryptography eliminates password theft
- Origin validation prevents phishing
- Authenticator attestation validates device authenticity
- Sign counter tracking detects credential cloning
- User verification (biometric/PIN) provides strong authentication

### JWT Structure

The Token service creates JWTs from `Claims` proto messages containing standard
claims:

- `sub` (subject) - Principal ID (authentication only)
- `iss` (issuer) - Token issuer
- `aud` (audience) - Intended services (e.g., \["api"\])
- `exp` (expiry) - Expiration timestamp
- `iat` (issued at) - Creation timestamp
- `jti` - Unique token ID

**Note**: JWTs contain NO authorization data (no scopes, no permissions, no
group memberships). Authorization is determined dynamically via ACLs on
resources.

## Future Enhancements

- OAuth2 social login (GitHub, Google, Apple) as alternative authentication
  method
- Enterprise SSO (SAML, LDAP) integration
- Additional MFA methods (TOTP, SMS) for high-security operations
- Device trust/fingerprinting for anomaly detection
- Suspicious login detection and alerting
- Conditional access policies based on authenticator characteristics

## Development Notes

Extraction and sanitization of incoming requests has been stripped from gateway
responsibilities and moved to the authentication system where it belongs.

This does mean some architectural changes and considerations:

- will receive authentication (zero-trust) verification from backend services
- need to sanitize client metadata (removes any spoofed `x-principal-id`)
- need to inject validated `x-principal-id` from JWT into backend metadata
