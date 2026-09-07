# Authentication API

## Design

- [Register](./docs/register.md)
- [Login](./docs/login.md)
- [Policy](./docs/policy.md)
- [Operator Responsibilities](./docs/operator.md)

## Logout

**There is no server-side logout operation.** Logout is entirely a client-side
action where the client deletes their access token from local storage.

**Important security consideration**: Deleted tokens remain cryptographically
valid until their expiry time. If an attacker obtained a copy of the token
before deletion, they can still use it until expiry. This is an accepted
tradeoff of stateless authentication.

**Mitigation**: Access token TTL (default: 24 hours, configurable) balances
security and UX.

## Re-authentication

When a principal's access token expires:

1. Client makes API request with expired token
2. Target service returns 401 Unauthenticated error
3. Client is directed to WebAuthn Login flow
4. Principal re-authenticates (biometric prompt or security key)
5. Client receives new access token (default: 24 hours, configurable)

**Identity Continuity**: WebAuthn credentials are mapped to principal IDs.
Re-authenticating with the same passkey always returns the same principal ID,
maintaining consistent identity across sessions.

**Proactive Re-authentication UX**:

Clients should prompt users to renew credentials before expiry:

```javascript
// Check token expiry
if (timeUntilExpiry < 24hours) {
  showBanner("Session expires soon. Renew now?");
}
```

This is deemed a satisfactory compromise because webauthn re-authentication is
typically near-instant (one biometric verification or security key touch).

## Security Considerations

**WebAuthn Security**:

- Cryptographic challenge-response prevents replay attacks
- Public key cryptography eliminates password theft
- User verification (biometric/PIN) provides strong authentication
