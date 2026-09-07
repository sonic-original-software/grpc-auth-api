# WebAuthn Operator Responsibilities

## Scope

This document is the authority for WebAuthn operator responsibilities,
configuration controls, defaults, permitted overrides, and required trust
material. [Policy](./policy.md) defines how those controls are evaluated.
[Register](./register.md) and [Login](./login.md) define message fields, flow
mechanics, persistence, and failure behavior.

## Responsibilities

The operator is responsible for:

- supplying the relying-party identity and request preferences
- selecting acceptance controls and understanding any documented departure from
  WebAuthn requirements
- supplying attestation trust material required by the selected attestation
  controls
- ensuring that clients support any configured re-verification requirement

## Runtime Configuration Resolution

The Authentication service receives operator configuration at runtime. For every
control:

- An absent value resolves to its documented default.
- A supplied value replaces the default. Values are never merged.

The service validates the complete effective configuration before using it. If
any value is invalid, unsupported, or inconsistent with another value, the
entire operator configuration is invalid. The Authentication service registers
itself as degraded and services no requests until it receives a valid runtime
configuration.

The Authentication service's runtime configuration reconciler owns this
validation. After resolving every operator value, it delegates policy-specific
validation to the selected policy implementation. A policy validation error
makes the entire effective operator configuration invalid.

The reconciler runs on every runtime configuration change. A ceremony already in
progress continues under the `validatedPolicyConfiguration` its handler retained
when the ceremony started. No ceremony in progress waits for reconciliation or
terminates because of it.

The reconciler verifies that the service can verify signatures for every
configured `pubKeyCredParams[].alg`. A configured algorithm the service cannot
verify makes the entire effective operator configuration invalid. This check
belongs to the reconciler because signature verification occurs in the flow
handlers, outside policy.

## Request Configuration

| Control                                          | Flow     | Allowed configuration                                 | Default                                                                                     |
| ------------------------------------------------ | -------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `timeout`                                        | Both     | Client ceremony hint in milliseconds                  | `300000` milliseconds (5 minutes)                                                           |
| `gracePeriod`                                    | Both     | Server wait extension in milliseconds                 | `5000` milliseconds (5 seconds)                                                             |
| `rp.id`                                          | Both     | Expected WebAuthn RP ID                               | Required operator value                                                                     |
| `rp.name`                                        | Register | WebAuthn RP display name                              | Required operator value                                                                     |
| `pubKeyCredParams[].alg`                         | Register | Nonempty ordered supported COSE algorithm identifiers | `-8` (EdDSA), `-7` (ES256), `-257` (RS256), in that order                                   |
| `authenticatorSelection.authenticatorAttachment` | Register | `platform`, `cross-platform`, or unset                | Unset                                                                                       |
| `userVerification`                               | Both     | `required`, `preferred`, or `discouraged`             | `required`                                                                                  |
| `hints[]`                                        | Both     | Ordered presentation preferences                      | Empty list                                                                                  |
| `extensions`                                     | Both     | Opaque extension inputs                               | Empty. Returned outputs are ignored; see [Extension Outputs](./policy.md#extension-outputs) |
| `attestation`                                    | Register | WebAuthn attestation conveyance preference            | `none`                                                                                      |
| `attestationFormats[]`                           | Register | Ordered WebAuthn attestation format preferences       | `["none"]`                                                                                  |

Register's `residentKey = "required"` and `requireResidentKey = true` are fixed
system requirements and are not operator controls.

The operator may change `timeout`. The operator is responsible for selecting a
duration that gives its users enough time to use their authenticators and for
provisioning infrastructure for the resulting upper bound on concurrent open
streams. Each flow's server wait is `timeout` plus `gracePeriod`.

`gracePeriod` absorbs the network delay in delivering the first response and
returning the second client message, so that a client observing its own
`timeout` is not cut off by the server first. A value too small terminates
ceremonies the client still considers live; a value too large raises the upper
bound on concurrent open streams in proportion to its share of the total wait.

`hints[]` and `authenticatorSelection.authenticatorAttachment` are independent
controls, and the reconciler does not constrain one against the other. WebAuthn
defines hints as non-binding guidance to the client that take precedence over
`authenticatorAttachment` where the two contradict, and advises setting
`authenticatorAttachment` to `cross-platform` alongside the `security-key` hint
for clients that do not recognize hints. The operator owns keeping the two
coherent.

## Acceptance Configuration

| Control                                                                  | Default  | Operator responsibility                                                                                                                                                                                           | Policy rule                                                                                    |
| ------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Origin enforcement                                                       | Disabled | The default deliberately omits WebAuthn's required origin validation; supply expected origins before enabling                                                                                                     | [Origin](./policy.md#origin)                                                                   |
| Cross-origin embedding enforcement                                       | Disabled | The default deliberately omits WebAuthn's required `crossOrigin` and `topOrigin` validation; decide whether cross-origin iframe use is permitted and supply allowed top-level origins before enabling             | [Cross-Origin Embedding](./policy.md#cross-origin-embedding)                                   |
| RP ID hash mismatch override                                             | Disabled | Enabling this deliberately departs from WebAuthn's expected-RP-ID verification requirement                                                                                                                        | [RP ID Hash](./policy.md#rp-id-hash)                                                           |
| Backup state without backup eligibility rejection                        | Enabled  | Disabling deliberately omits WebAuthn's unconditional check on the returned flags byte                                                                                                                            | [Backup State Without Backup Eligibility](./policy.md#backup-state-without-backup-eligibility) |
| Backup eligibility change rejection                                      | Enabled  | A credential whose reported BE flag changes is rejected on every subsequent Login and the principal must register a new credential; disabling keeps such a credential usable and gives up the substitution signal | [Backup Eligibility Change](./policy.md#backup-eligibility-change)                             |
| Signature-counter anomaly rejection                                      | Disabled | Leaving this disabled is strongly recommended; enabling it blocks the legitimate holder of a cloned credential while leaving the attacker able to authenticate                                                    | [Signature Counter](./policy.md#signature-counter)                                             |
| Login attestation-trust enforcement                                      | Disabled | Enabling is recommended for deployments that rely on attestation trust; supply current trust material and revocation information                                                                                  | [Login Attestation Trust](./policy.md#login-attestation-trust)                                 |
| Login `uvInitialized` transition without additional-factor authorization | Disabled | Enabling deliberately omits WebAuthn's recommendation for additional-factor authorization                                                                                                                         | [uvInitialized Transition](./policy.md#uvinitialized-transition)                               |

The operator selects `userVerification` through
[Request Configuration](#request-configuration). Its evaluation is defined by
[User Verification](./policy.md#user-verification).

## Credential Record Storage

The operator selects whether to retain the optional WebAuthn credential-record
field `rpId`. This storage control is disabled by default. Its source and
persistence mechanics are defined by
[Register](./register.md#atomic-persistence).

## Re-verification

An operator may require the future dedicated re-verification RPC as the
`uvInitialized` transition path. That RPC has not been designed. Clients would
need to implement its custom flow before an operator could require it.

## Attestation

The operator supplies:

- the allowed WebAuthn attestation statement format identifiers
- the allowed WebAuthn attestation types
- trust-anchor certificate bytes
- known intermediate-certificate bytes
- certificate-status requirements needed by the selected attestation controls

The default allowed attestation format set is `none`. Every configured allowed
format identifier must have a corresponding verifier in the configured policy
implementation. A format unsupported by that policy implementation makes the
entire runtime configuration invalid.

This allowlist and the `attestationFormats[]` request preference in
[Request Configuration](#request-configuration) are independent controls, and
the reconciler does not constrain one against the other. WebAuthn defines
`attestationFormats[]` as an ordered preference an authenticator may disregard,
while this allowlist is what policy accepts in a returned `fmt`. The operator
owns keeping the two coherent; a preference for a format outside the allowlist
produces registrations that policy rejects.

The allowed attestation types form a separate allowlist of types acceptable
under operator policy. Evaluation order is defined in
[Attestation](./policy.md#attestation). The default allowlist contains only
`None`. Operators may replace it with other sets of WebAuthn attestation types
supported by the policy implementation.

### Attestation Trust Downgrade

The operator may enable attestation trust downgrade to `Self` for Register and
enabled Login attestation-trust evaluation. This control is disabled by default.
Enabling it requires `Self` in the allowed attestation types; otherwise the
effective configuration is invalid. Operators enabling it accept credentials
without assurance of a particular authenticator model when certificate trust
assessment fails. Evaluation is defined in
[Attestation Trust Downgrade](./policy.md#attestation-trust-downgrade).

The concrete certificate-status configuration has not yet been decided. Trust
material is supplied through the service configuration interface without
assuming a filesystem, container runtime, or operating system. Attestation
evaluation is defined by [Policy](./policy.md#attestation).
