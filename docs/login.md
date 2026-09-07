# WebAuthn Login Design

## Scope

This design covers authentication using an existing discoverable WebAuthn
credential.

A successful Login flow returns the credential record's `principalId` with a
[grant](./grant.md) the caller redeems for a signed JWT.

## RPC Structure

Login is a bidirectional streaming RPC:

```text
Client: LoginStart
Server: PublicKeyCredentialRequestOptions
Client: PublicKeyCredential containing AuthenticatorAssertionResponse
Server: LoginResult
```

Messages received out of order terminate the flow.

Temporary flow state exists in the active stream handler.

When sending the first response, the handler starts a server-enforced wait for
the second client message. The wait limit is the `timeout` value sent in the
first response plus the configured `gracePeriod` defined in
[Operator Responsibilities](./operator.md#request-configuration). The handler
terminates the flow when that limit expires, regardless of whether the client
enforces the `timeout` hint.

## LoginStart

The client opens the stream and sends an empty `LoginStart` message.

The Login flow uses discoverable credentials, so `LoginStart` contains no
principal, user-handle, or credential identifier.

## PublicKeyCredentialRequestOptions

After receiving `LoginStart`, the handler:

1. Generates a cryptographically random challenge of at least 16 bytes and
   retains its exact bytes.
2. Loads the operator-controlled response values defined in
   [Operator Responsibilities](./operator.md#request-configuration).
3. Sets `allowCredentials` to an empty list.

The handler retains the challenge and the `validatedPolicyConfiguration` in
effect when the stream opened for the active flow.

The first response contains:

```text
challenge
timeout

rpId

allowCredentials[]
userVerification

hints[]

extensions
```

The response sets:

```text
allowCredentials[] = []
```

The server leaves `allowCredentials` empty because Login begins without an
identified principal and requires a discoverable credential.

## PublicKeyCredential and AuthenticatorAssertionResponse

The handler's second request message contains:

```text
rawId
type
authenticatorAttachment
clientExtensionResults

response.clientDataJSON
response.authenticatorData
response.signature
response.userHandle
```

`rawId` contains the credential identifier bytes. `type` is `"public-key"`.
`authenticatorAttachment` is client-reported and may be unset, and
`clientExtensionResults` is opaque.

## Handler Processing

The service UTF-8 decodes `response.clientDataJSON` once, strips any leading
byte-order mark, and parses the resulting JSON into `decodedClientDataJSON`,
containing:

```text
type
challenge
origin
crossOrigin
topOrigin
```

`crossOrigin` and `topOrigin` may be absent.

The service separately decodes `response.authenticatorData` once into
`decodedAuthenticatorData`, containing:

```text
rpIdHash
flags
signCount
extensions
```

`signCount` is a 32-bit unsigned big-endian integer.

The parsing result retains the exact original `clientDataJSON` and
`authenticatorData` bytes.

The handler ignores `clientExtensionResults` and the decoded `authenticatorData`
extensions, as defined by [Extension Outputs](./policy.md#extension-outputs).

The handler verifies:

```text
PublicKeyCredential.type == "public-key"

decodedClientDataJSON.type == "webauthn.get"

decodedClientDataJSON.challenge
    == base64url encoding of the challenge retained by the stream handler

decodedAuthenticatorData.flags.UP is set
```

Malformed client or authenticator data, missing required values, or a failed
check terminates Login without returning a grant.

## Credential Record

The handler rejects `PublicKeyCredential.rawId` values larger than 1,023 bytes
before attempting credential lookup.

Login resolves the stored credential record using `rawId` as the `credentialId`:

```text
credentialId
    → credentialRecord
```

A `credentialId` with no stored credential record terminates Login without
returning a grant.

Because Login begins without an identified principal, `response.userHandle` must
be present. The handler verifies that it equals the `principalId` in the
credential record. A missing or mismatched value terminates Login without
returning a grant.

## Signature Verification

After resolving the credential record, the handler computes the SHA-256 hash of
the original `response.clientDataJSON` bytes. It uses the stored
`credentialPublicKey` to verify that `response.signature` is a valid signature
over the binary concatenation of `response.authenticatorData` and that hash.

An invalid signature terminates Login without returning a grant.

## Policy Evaluation

After mechanical validation and signature verification, the handler consults the
configured [policy](./policy.md) at each of the following checkpoints, in order:

```text
originAllowed(decodedClientDataJSON.origin)

crossOriginAllowed(decodedClientDataJSON.crossOrigin,
                   decodedClientDataJSON.topOrigin)

rpIdHashAccepted(decodedAuthenticatorData.rpIdHash)

backupFlagsAccepted(decodedAuthenticatorData.flags.BE,
                    decodedAuthenticatorData.flags.BS)

backupEligibilityUnchanged(decodedAuthenticatorData.flags.BE,
                           credentialRecord.backupEligible)

userVerificationSatisfied(decodedAuthenticatorData.flags.UV,
                          credentialRecord.uvInitialized)

signCountAccepted(decodedAuthenticatorData.signCount,
                  credentialRecord.signCount)

storedAttestationAccepted(credentialRecord.attestationObject,
                          credentialRecord.attestationClientDataJSON)
```

Values come from the shared parsing stage and from the resolved credential
record. Policy answers each query from the `validatedPolicyConfiguration`
retained for this flow, which supplies the expected `rpId`, the requested
`userVerification`, and every acceptance control.

A `false` answer at any checkpoint terminates Login without returning a grant.
No later checkpoint runs.

After every checkpoint answers `true`, the handler requests one atomic update:

```text
credential record
    signCount   = decodedAuthenticatorData.signCount
    backupState = decodedAuthenticatorData.flags.BS

principal record
    grantHash for the grant generated for this flow
    lastAuthenticatedDate = the current UNIX timestamp
```

[Grant](./grant.md) defines how the grant is generated and how its hash is
stored. The handler retains the grant itself for [LoginResult](#loginresult).

When the credential record's `uvInitialized` is `false` and
`decodedAuthenticatorData.flags.UV` is set, the handler asks one further query:

```text
uvTransitionAuthorized(decodedAuthenticatorData.flags.UV,
                       credentialRecord.uvInitialized)
```

A `true` answer includes `uvInitialized = true` in the same update. A `false`
answer leaves the stored value unchanged. Both answers accept the Login, so this
query decides a field write rather than the outcome.

All permitted changes commit together. If the update fails, both records remain
unchanged and no grant is returned.

Concurrent Logins using one credential each read the record and then write it,
and the last update to commit determines the stored `signCount`. WebAuthn tests
only that a returned counter is greater than the stored counter, so a later
assertion exceeds either racing value and the record converges without
intervention.

Concurrent Logins for one principal write the principal record's `grantHash`,
whether or not they use the same credential. The last write wins and the caller
holding the overwritten grant is refused at redemption, as defined by
[Concurrency](./grant.md#concurrency). That caller runs Login again.

## LoginResult

After the atomic update commits, the Authentication system returns:

```text
principalId
grant
```

`principalId` is the credential record's. `grant` is the value whose hash that
update stored. The caller redeems the pair for a signed JWT whose `sub` claim is
that `principalId`, as defined by [Grant](./grant.md).

Rerunning Login is the correct recovery at every failure point, including a
`LoginResult` the caller never receives.

## Error Reporting

Field validation failures identify the invalid fields to the caller. Other
failures return the status appropriate to the error, preserving its detail.

The service does not withhold failure detail. Its security rests on
cryptographic verification of the assertion and attestation, and concealing
which check failed does not contribute to it.
