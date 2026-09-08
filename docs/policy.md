# WebAuthn Policy

## Scope

This document defines the queries the [Register](./register.md) and
[Login](./login.md) handlers make of the configured policy, and how policy
answers them. The flow documents define message fields, mechanical validation,
the point in the flow at which each query runs, and the consequence of each
answer. [Operator Responsibilities](./operator.md) is the authority for
configuration, defaults, permitted overrides, required trust material, and
operator responsibilities.

Each handler holds the ceremony's parsed values and asks policy narrow
questions. A query receives the values it compares and answers from the
configuration validated for that ceremony. Policy holds no ceremony state and
never parses a ceremony message.

Every query answers `true` or `false`. A `false` answer fails the ceremony,
except for [uvInitialized Transition](#uvinitialized-transition), which decides
a field write.

A query whose control is disabled answers `true`.

The policy implementation exposes configuration validation to the Authentication
service's runtime configuration reconciler:

```text
policy.validateConfiguration(effectiveOperatorConfiguration)
    → validatedPolicyConfiguration or error
```

The policy implementation validates every policy-owned configuration value, all
policy-specific cross-field constraints, the inputs and trust material required
by enabled controls, and the implementation capabilities required by those
controls. This includes providing a verifier for every allowed attestation
format. Ceremony handlers do not validate operator configuration.

Each handler retains the `validatedPolicyConfiguration` in effect when its
ceremony started and answers every query for that ceremony from it. A
configuration change while a ceremony is open does not affect that ceremony. The
retained configuration supplies the expected RP ID and the requested
`userVerification`, which are the values the handler sent to the client.

## Policy Stance

Client-reported values are untrusted inputs. Their presence or agreement with an
expected value does not independently establish that the client is trustworthy.
Treating those checks as proof of client trust would create false assurance.

As policy decisions are made, each control should document its query and
answering behavior here. Its configuration, default, and any deliberate
departure from WebAuthn requirements should be documented in
[Operator Responsibilities](./operator.md).

## Origin

```text
originAllowed(origin)
```

When origin enforcement is enabled, policy answers `false` if `origin` does not
match an expected origin. The controlling operator setting is defined in
[Operator Responsibilities](./operator.md).

WebAuthn advises against listing a subdomain of the RP ID as an expected origin.
Credentials are scoped to the RP ID, so any origin in that scope can exercise
them, and code running on a listed subdomain can obtain valid assertions for the
whole relying party. An operator that lists one must serve no untrusted content
on it.

## Cross-Origin Embedding

```text
crossOriginAllowed(crossOrigin, topOrigin)
```

When enforcement is enabled, policy answers `false` if either holds:

- `crossOrigin` is present and `true` while cross-origin iframe use is not
  allowed.
- `topOrigin` is present while cross-origin iframe use is not allowed, or
  `topOrigin` does not match a configured top-level origin.

The controlling settings are defined in
[Operator Responsibilities](./operator.md).

## RP ID Hash

```text
rpIdHashAccepted(rpIdHash)
```

Policy compares `rpIdHash` with the SHA-256 hash of the expected RP ID in the
retained configuration and answers `false` on a mismatch. When the mismatch
override is enabled, policy answers `true` on a mismatch. The controlling
setting is defined in [Operator Responsibilities](./operator.md).

## Backup State Without Backup Eligibility

```text
backupFlagsAccepted(be, bs)
```

When enforcement is enabled, policy answers `false` if the backup state (BS)
flag is set while the backup eligibility (BE) flag is unset. A credential that
is not backup eligible cannot be backed up, so an authenticator reporting that
pair is malformed.

Register and Login both ask this query. WebAuthn states the check
unconditionally. The controlling setting is defined in
[Operator Responsibilities](./operator.md).

## Backup Eligibility Change

```text
backupEligibilityUnchanged(be, storedBackupEligible)
```

Login asks this query. When enforcement is enabled, policy answers `false` if
the two values differ.

A credential's backup eligibility is fixed when the credential is created and
the credential record's `backupEligible` is never updated after registration. A
difference is therefore either an authenticator other than the one that
registered the credential, or a platform defect that changed the reported flag.
Policy cannot distinguish the two and answers `false` for both.

WebAuthn requires this comparison only of relying parties that use backup state
in their business logic. This service performs the comparison whether or not
backup state is used that way. The controlling setting is defined in
[Operator Responsibilities](./operator.md).

## Extension Outputs

No query reads client extension outputs or authenticator extension outputs. Both
flows decode them and neither acts on them, including outputs the service did
not request. WebAuthn permits a relying party to ignore any or all extension
outputs.

Requiring a specific extension and enforcing its output is reserved for a later
design. Doing so requires deciding which extensions this service depends on and
adding a query that reads `clientExtensionResults`.

## User Verification

```text
userVerificationSatisfied(uv)                       Register
userVerificationSatisfied(uv, storedUvInitialized)  Login
```

When the retained configuration requested `userVerification = "required"`,
policy answers `false` if the UV flag is unset.

Login supplies the credential record's stored `uvInitialized`. Policy must not
rely on the returned UV flag as an authentication factor while that stored value
is `false`, including the Login in which
[uvInitialized Transition](#uvinitialized-transition) would change it to `true`.
So when `userVerification = "required"` and `storedUvInitialized` is `false`,
policy answers `false` and the Login fails whatever the UV flag reports.

Register creates the credential record only after its checks pass, so no stored
`uvInitialized` exists when Register asks this query. Register's form takes the
UV flag alone.

The controlling settings and defaults are defined in
[Operator Responsibilities](./operator.md).

## Signature Counter

```text
signCountAccepted(signCount, storedSignCount)
```

Login asks this query. If either value is nonzero and rejection is enabled,
policy answers `false` when the returned counter did not increase. WebAuthn
tests only that the returned counter is greater than the stored counter. An
authenticator may keep one counter across every credential and relying party,
and assertions the service never receives still advance it, so consecutive
values are not required.

A counter that did not increase is a signal, but not proof, of a cloned or
malfunctioning authenticator or out-of-order request processing.

An attacker holding a cloned credential controls the counter it reports and can
report any value. Rejection therefore falls on the legitimate holder, whose
authenticator reports the lower counter, while the cloned credential continues
to authenticate. Leaving this control disabled is strongly recommended.

The controlling setting is defined in
[Operator Responsibilities](./operator.md).

## uvInitialized Transition

```text
uvTransitionAuthorized(uv, storedUvInitialized)
```

Login asks this query when the credential record's `uvInitialized` is `false`
and the returned UV flag is set. Policy answers whether the handler writes
`true` into the stored `uvInitialized` as part of the atomic credential-record
update.

This query decides a field write. Both answers accept the Login. A `false`
answer leaves the stored value at `false`.

Policy must not treat the returned UV flag as an authentication factor for the
Login in which it answers `true` here. The configured transition behavior and
the undeveloped additional-factor path are defined in
[Operator Responsibilities](./operator.md).

## Attestation

```text
attestationAccepted(fmt, attStmt, authDataBytes, clientDataHash)
```

Register asks this query. The handler supplies the SHA-256 hash it computed over
the exact `clientDataJSON` bytes and the exact `authData` bytes it retained.
Format matching, verification, certificate trust assessment, downgrade, and type
acceptance all happen behind this query. The handler receives an answer and
never sees the attestation type or the trust path.

Policy matches `fmt` case-sensitively against the operator-configured allowed
WebAuthn attestation statement format identifiers and answers `false` if `fmt`
is not allowed.

Using the verification procedure defined for `fmt`, policy verifies `attStmt`
against `authDataBytes` and `clientDataHash`. A failed verification answers
`false`. Policy applies attestation-trust requirements only after this
verification succeeds.

The format-specific verification procedure determines the attestation type. For
`None` and `Self`, policy proceeds directly to type acceptance. For
certificate-based attestation, policy first completes certificate trust
assessment and any permitted downgrade.

For certificate-based attestation, verification uses the trust-anchor and known
intermediate-certificate bytes supplied through the service configuration
interface. It must build the attestation certificate chain to a supplied trust
anchor and check the available certificate-status information for intermediate
certificate authorities. Operator ownership of that material and those
requirements is defined in
[Operator Responsibilities](./operator.md#attestation). Failed certificate trust
assessment is handled by
[Attestation Trust Downgrade](#attestation-trust-downgrade).

Policy then checks the resulting attestation type against the
operator-configured allowed attestation types. After a permitted downgrade, this
check uses `Self`; otherwise it uses the verified type. An unlisted resulting
type answers `false`. An unlisted original type does not answer `false` before
the certificate trust assessment and downgrade decision. A type-acceptance
failure alone does not trigger downgrade.

The format, AAGUID, attestation type, trust path, and trust result are derived
during evaluation rather than persisted as duplicate credential-record fields.

## Attestation Trust Downgrade

After format-specific verification succeeds, if certificate trust assessment
fails, policy evaluates the configured downgrade control. When enabled, policy
treats the credential as `Self` for the current evaluation and proceeds to type
acceptance. Otherwise the attestation query answers `false`. All other
applicable acceptance checks must still pass. Downgrade does not override a
failed format-specific verification or a failed Login assertion signature
verification.

This rule applies to [Attestation](#attestation) and
[Login Attestation Trust](#login-attestation-trust), including certificate trust
failures caused by expiration or revocation. It provides no authenticator-model
assurance and preserves the original stored attestation evidence. Each
evaluation derives its result using current policy.

WebAuthn permits policy to treat an attestation that passes format-specific
verification but fails trust assessment as self-attestation. The control and
default are defined in
[Operator Responsibilities](./operator.md#attestation-trust-downgrade).

## Login Attestation Trust

```text
storedAttestationAccepted(storedAttestationObject, storedAttestationClientDataJSON)
```

Login asks this query. When the control is enabled, policy re-evaluates the
registration evidence retained on the credential record using the
[attestation evaluation](#attestation) and current operator trust requirements.
Policy decodes that stored evidence itself; no handler has parsed it.

Certificate trust assessment uses the current time against certificate validity
periods and uses supplied revocation information. Failed certificate trust
assessment follows [Attestation Trust Downgrade](#attestation-trust-downgrade).
Policy answers `false` if attestation verification fails or acceptance
requirements remain unsatisfied after that decision.

This additional Login policy requires registration attestation to satisfy
current trust requirements or the configured downgrade rules. It adds ongoing
attestation-trust enforcement beyond WebAuthn's standard Login verification
procedure. Evaluation occurs when the credential is used for Login.

The controlling setting and default are defined in
[Operator Responsibilities](./operator.md#acceptance-configuration).
