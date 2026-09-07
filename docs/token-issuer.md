# Token Issuer

## Scope

This document is the authority for the Token Issuer service: the key it holds,
the claims it produces, and what it establishes before producing them.
[Grant](./grant.md) defines the value a caller presents.
[Principal Service](./principal.md) defines the two methods this service calls.

## Responsibilities

The service holds the signing key and is the only service that signs. The key
never leaves it.

The service keeps no state between requests, holds no record of what it has
minted, and reads and writes no store of its own.

The service names no subject of its own. Every token it produces names a subject
it established a claim to during that request.

## Key Custody

One signing key is in effect at a time. Replacing it takes effect on the next
minting, and every token signed with the replaced key stops verifying. Nothing
else holds the signing key, so nothing else produces a token this service would
recognize as its own.

## Claims

A minted token carries:

```text
sub   the subject whose stored hash the presented grant matched
aud   the audience this service is configured with
iss   the issuer identity this service is configured with
exp   the expiration supplied by the caller, or never when omitted
iat   the time of minting
nbf   the not-before supplied by the caller, or the time of minting when omitted
```

`aud` comes from configuration rather than the request. Every token this service
mints names the same audience, and a caller cannot choose who its token claims
to be for.

When A caller doesn't supply the `optional exp`, that token does not expire. It
carries no `exp` claim, which is what every JWT implementation reads as no
expiration. Replacing the signing key is what ends such a token's life. A caller
holding a non-expiring token holds one for a subject it authenticated as, so the
lifetime is the caller's to choose. Callers wanting a session rather than an API
token are advised to request 24 hours.

## IssueToken

```text
IssueToken(subject, grant, exp, nbf) → token
```

The service calls [GetGrantHash](./principal.md#getgranthash) with `subject`,
computes the hash of the presented `grant`, and compares the two in constant
time. A difference refuses the request, and nothing has been changed.

On a match the service calls [ClearGrant](./principal.md#cleargrant) with
`subject` and the grant. A clear that does not land refuses the request, because
another caller changed the stored value between the read and the clear and
single use can no longer be established.

After the clear lands the service mints the claims above and signs them.

## Why the Comparison Is Here

The service compares the hashes itself rather than asking the Principal Service
whether they match. A service that mints on an answer it was handed holds no
proof of its own, and anything able to answer in the Principal Service's place
would obtain a token for any subject. Comparing locally means the only thing the
service acts on is a value its own caller supplied.

Carrying the stored hash over the network costs nothing, since a hash yields
nothing without the grant that produced it, and only a grant passes the
comparison.

The clear runs after the comparison rather than as part of the read, so a caller
presenting nonsense destroys no grant that someone else is about to redeem.

## Refusals

The service refuses a malformed request before calling anything. It refuses a
subject with no stored hash, a stored hash that is NULL, a grant that does not
match, and a clear that does not land.

Failure detail is not withheld. Every refusal follows from a grant the caller
presented, so a refusal tells the caller nothing it did not already know.
