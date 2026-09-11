# WebAuthn Register Design

## Scope

This design covers first-time principal registration using a discoverable
WebAuthn credential.

It does not cover Login, associating additional credentials with an existing
principal, operator-policy implementation, or JWT signing-key management.

A successful Register flow creates a principal and a credential record that
references it:

```text
credentialId
    → credentialRecord
        → principalId
```

and returns the new `principalId` with a
[grant](../../services/principal/docs/grant.md) the caller redeems for a signed
JWT.

## RPC Structure

Register is a bidirectional streaming RPC:

```text
Client: RegisterStart
Server: PublicKeyCredentialCreationOptions
Client: PublicKeyCredential containing AuthenticatorAttestationResponse
Server: RegisterResult
```

The request and response messages use `oneof` fields to represent their steps.
The handler verifies that each received message contains the expected `oneof`
variant for that step.

Messages received out of order terminate the flow.

## RegisterStart

The initial request contains only optional cosmetic values:

```text
name
displayName
```

Neither value establishes identity or affects authorization. Missing values may
be represented as empty strings.

Both fields must contain valid UTF-8. The handler preserves supplied values
without case conversion or Unicode normalization.

## PublicKeyCredentialCreationOptions

After receiving `RegisterStart`, the handler:

1. Generates a candidate `principalId` and uses its bytes as WebAuthn `user.id`.
2. Generates a cryptographically random challenge of at least 16 bytes.
3. Loads the operator-controlled response values defined in
   [Operator Responsibilities](./operator.md#request-configuration).

The `principalId` must be opaque, contain no personally identifying information,
and be between 1 and 64 bytes inclusive. WebAuthn constrains the `user.id` byte
sequence itself and rejects any other length; the constraint does not apply to
an encoding of that sequence. The `principalId` does not identify a persisted
principal until the atomic storage operation succeeds.

A UUIDv4 satisfies these constraints and is adequate for most deployments.
Versions that embed a timestamp or MAC address do not, because they place
structure in a value WebAuthn requires to be opaque.

The first response contains:

```text
challenge
timeout

rp.id
rp.name

user.id
user.name
user.displayName

pubKeyCredParams[].type
pubKeyCredParams[].alg

excludeCredentials[].type
excludeCredentials[].id
excludeCredentials[].transports[]

authenticatorSelection.authenticatorAttachment
authenticatorSelection.residentKey
authenticatorSelection.requireResidentKey
authenticatorSelection.userVerification

hints[]

attestation
attestationFormats[]

extensions
```

Operator-controlled field population is defined in
[Operator Responsibilities](./operator.md#request-configuration). The remaining
system-defined mappings are:

```text
user.id           = principalId
user.name         = requested name or empty string
user.displayName = requested displayName or empty string

pubKeyCredParams[].type = "public-key"

excludeCredentials[] = []

authenticatorSelection.residentKey         = "required"
authenticatorSelection.requireResidentKey = true
```

`user` carries the principal record's fields, and this response precedes the
record. Its `creationDate` and `lastAuthenticatedDate` are therefore unset and
carry no meaning here. [Atomic Persistence](#atomic-persistence) establishes
both.

`excludeCredentials[]` is empty. Register creates a new principal on every call
and has no identified principal whose existing credentials could populate the
list. A caller may register the same authenticator as many times as that
authenticator permits, and each call produces an independent principal.

Authenticators key discoverable credentials by RP ID and user handle. Each
Register issues a fresh `principalId` and therefore a fresh user handle, so a
repeat registration adds a discoverable credential rather than replacing an
earlier one. Each consumes authenticator storage, and Login offers every one of
them.

`residentKey = "required"` is a system requirement. Login sends an empty
`allowCredentials`, so a credential that is not discoverable can never be found
and is unusable.

The handler cannot confirm that requirement was honored. Authenticator data
carries no discoverability bit, and WebAuthn reports the property only through
the `credProps` extension's `rk` output, which this service ignores along with
every other extension output. An authenticator that disregards the request
therefore registers a credential that no later Login can use, and the failure
surfaces at that Login rather than during Register.

The handler retains the candidate `principalId`, challenge, the
`validatedPolicyConfiguration` in effect when the stream opened, and the
algorithm identifiers offered in `pubKeyCredParams` while the stream remains
open.

## PublicKeyCredential and AuthenticatorAttestationResponse

The handler's second request message contains:

```text
rawId
type
authenticatorAttachment
clientExtensionResults

response.clientDataJSON
response.attestationObject
response.transports[]
```

`rawId` contains the credential identifier bytes. `type` is `"public-key"`.
`authenticatorAttachment` is client-reported and may be unset,
`clientExtensionResults` is opaque, and `response.transports[]` may be empty.

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

The service separately decodes `response.attestationObject` once into
`decodedAttestationObject`, containing:

```text
fmt
authData
attStmt
```

The service decodes `authData` once into `decodedAuthData`, containing:

```text
rpIdHash
flags
signCount

aaguid
credentialId
credentialPublicKey

extensions
```

`signCount` is a 32-bit unsigned big-endian integer. Fields following it are
interpreted according to the `authData` flags. The parsing result retains the
exact original `clientDataJSON` and `attestationObject` bytes, and the exact
original `authData` bytes as `authDataBytes`.

The handler computes the SHA-256 hash of the exact `response.clientDataJSON`
bytes as `clientDataHash` and retains it for
[Attestation](./policy.md#attestation).

The handler ignores `clientExtensionResults` and `decodedAuthData.extensions`,
as defined by [Extension Outputs](./policy.md#extension-outputs).

Malformed inputs, an unset attested credential data (AT) flag, or missing
required attested credential data terminate Register before policy evaluation or
persistence. The AT flag reports whether the authenticator included the
`aaguid`, `credentialId`, and `credentialPublicKey` that Register requires.

The handler then verifies:

```text
PublicKeyCredential.type == "public-key"

decodedClientDataJSON.type == "webauthn.create"

decodedClientDataJSON.challenge
    == base64url encoding of the challenge retained by the stream handler

PublicKeyCredential.rawId
    == decodedAuthData.credentialId

decodedAuthData.credentialPublicKey.alg
    is one of the algorithm identifiers offered in pubKeyCredParams

decodedAuthData.flags.UP is set

byteLength(decodedAuthData.credentialId) <= 1,023
```

A failed check rejects registration before policy evaluation or persistence.

## Policy Evaluation

After the checks in [Handler Processing](#handler-processing), the handler
consults the configured [policy](./policy.md) at each of the following
checkpoints, in order:

```text
originAllowed(decodedClientDataJSON.origin)

crossOriginAllowed(decodedClientDataJSON.crossOrigin,
                   decodedClientDataJSON.topOrigin)

rpIdHashAccepted(decodedAuthData.rpIdHash)

backupFlagsAccepted(decodedAuthData.flags.BE,
                    decodedAuthData.flags.BS)

userVerificationSatisfied(decodedAuthData.flags.UV)

attestationAccepted(decodedAttestationObject.fmt,
                    decodedAttestationObject.attStmt,
                    authDataBytes,
                    clientDataHash)
```

Every value comes from the shared parsing stage. Policy answers each query from
the `validatedPolicyConfiguration` retained for this flow, which supplies the
expected RP ID, the requested `userVerification`, and every acceptance control.

A `false` answer at any checkpoint terminates registration without persistence
or a returned grant. No later checkpoint runs.

## Atomic Persistence

After every checkpoint answers `true`, the handler requests one atomic storage
operation that:

```text
insert principal keyed by the candidate principalId
    with grantHash for the grant generated for this flow
    and name = requested name or empty string
    and displayName = requested displayName or empty string
    and creationDate = the registration timestamp
    and lastAuthenticatedDate = that same timestamp
insert credential keyed by credentialId = PublicKeyCredential.rawId
    with principalId referencing that principal
    and credentialPublicKey = decodedAuthData.credentialPublicKey
    and signCount = decodedAuthData.signCount
    and uvInitialized = decodedAuthData.flags.UV
    and transports = response.transports
    and backupEligible = decodedAuthData.flags.BE
    and backupState = decodedAuthData.flags.BS
    and attestationObject = response.attestationObject
    and attestationClientDataJSON = response.clientDataJSON
commit both records together
```

When enabled by
[Operator Responsibilities](./operator.md#credential-record-storage), the same
atomic operation also stores the optional `rpId` field:

```text
rpId = rp.id issued for this registration
```

The registration timestamp is the UNIX timestamp the handler computes
immediately before requesting the atomic operation. `creationDate` and
`lastAuthenticatedDate` both hold that value, so a principal that has never
logged in reports the moment it was registered.

[Grant](../../services/principal/docs/grant.md) defines how the grant is
generated and how its hash is stored. The handler retains the grant itself for
[RegisterResult](#registerresult).

The datastore implementation must enforce `principalId` uniqueness,
`credentialId` uniqueness, and the credential record's reference to the
principal as part of that atomic operation. A relational implementation uses
primary-key and foreign-key constraints in one transaction. An ephemeral map
implementation may provide equivalent behavior by protecting both maps with one
exclusive critical section.

The credential record's `type` is the fixed WebAuthn value `"public-key"` and
does not require physical storage. If WebAuthn adds another credential type,
supporting it will likely require a deeper redesign of the credential schema and
its type-specific verification data anyway.

The handler does not perform a separate credential lookup before insertion. If
either identifier already exists or either record cannot be created, the
datastore fails the complete operation. No principal or credential record is
retained and no grant is returned.

## RegisterResult

Only after atomic persistence succeeds does the handler send the final streamed
`RegisterResult`:

```text
principalId
grant
```

`grant` is the value whose hash the atomic persistence operation stored. The
caller redeems the pair for a signed JWT whose `sub` claim is that
`principalId`, as defined by [Grant](../../services/principal/docs/grant.md).

## Failure and Lifetime Behavior

When sending the first response, the handler starts a server-enforced wait for
the second client message. The wait limit is the `timeout` value sent in the
first response plus the configured `gracePeriod` defined in
[Operator Responsibilities](./operator.md#request-configuration). The handler
terminates the flow when that limit expires, regardless of whether the client
enforces the `timeout` hint.

If the stream disconnects, times out, or its server process dies before
completion:

```text
no temporary registration state is recovered
no partial principal is retained
a later registration attempt starts a new flow
```

The system requires no temporary shared server-side registration store.
Temporary state exists only in the active stream handler.

A returned error means atomic persistence did not occur, and the caller reruns
Register.

A caller that never receives `RegisterResult` cannot tell whether persistence
occurred, because a handler that dies returns nothing. Rerunning Register
creates a second principal, since Register creates a new principal on every
call, and the first becomes unreachable. That caller resolves the question
through [Login](./login.md):

```text
Login returns a result
    the principal was persisted and the caller holds its grant

Login resolves no credential record for the presented credentialId
    persistence did not occur and the caller runs Register

Login fails any other way
    the question remains open and the caller runs Login again
```

The authenticator retains the credential it created whether or not the service
persisted one, so Login has that credential to offer in either case.

The third outcome covers a cancelled ceremony, an unavailable authenticator, a
policy refusal, and a `LoginResult` that never arrives. None of them establish
whether the principal exists.

## Error Reporting

Field validation failures identify the invalid fields to the caller. Other
failures return the status appropriate to the error, preserving its detail.

The service does not withhold failure detail. Its security rests on
cryptographic verification of the assertion and attestation, and concealing
which check failed does not contribute to it.
