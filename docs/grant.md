# Grant

## Scope

This document is the authority for grants: how a flow produces one, how it is
stored, and what the token issuer requires before it mints.
[Register](./register.md) and [Login](./login.md) define the point in each flow
at which a grant is produced and what their result messages carry.

A grant is a single-use secret bound to one principal. Its holder redeems it at
the token issuer for a signed JWT whose `sub` claim is that principal's
`principalId`.

The token issuer is publicly reachable and mints for the `principalId` on the
record whose stored hash the presented grant matches. It accepts no
caller-supplied subject.

The Authentication service holds no token signing key and neither constructs nor
parses a JWT.

## Generation

The flow generates 32 bytes from a cryptographically secure random source. Those
bytes are the grant. The flow computes the SHA-256 digest of those exact bytes
and stores the digest.

No salt and no key derivation function is applied. Both defend an input space an
attacker can search. Thirty-two random bytes are not such a space.

## Storage

The digest is stored in the `grantHash` field of the principal record, written
by the atomic commit the flow already performs. A principal with no outstanding
grant stores NULL.

The grant occupies a field on a record that exists for the life of the
principal, so no row is created and no storage accrues.

## Redemption

The holder presents the `principalId` and the grant:

```text
IssueToken(principalId, grant)
```

The issuer asks the [Principal Service](./principal.md) for the `grantHash`
stored on that principal. It computes the SHA-256 digest of the presented grant
itself and compares the two in constant time.

The issuer refuses when:

- no principal record exists for the supplied `principalId`
- the stored `grantHash` is NULL
- the computed digest does not equal the stored `grantHash`

A NULL field matches no presented value.

The comparison belongs to the issuer because the issuer is what mints. An issuer
told which subject to sign for holds no proof of its own, so it performs the
comparison rather than receiving its result. The stored hash may travel to reach
it, since a hash yields nothing without the grant that produced it.

On a match the issuer asks the Principal Service to clear the field, supplying
the grant. That service hashes it again and clears only while the stored value
still equals the result, so clearing costs what minting costs and no caller
destroys a pending grant it could not have redeemed. The mint follows a
successful clear. When the clear does not land, another operation changed the
field between the read and the clear, and the issuer refuses. Single use rests
on that conditional clear, so an issuer that cannot establish it mints nothing.

Reading precedes clearing, so a presented grant that does not match leaves the
stored one intact and no caller can destroy a pending grant by presenting
nonsense.

The minted JWT's `sub` claim is the `principalId` whose stored hash matched.

## Concurrency

Two flows completing for one principal both write the field. The last write
wins, and the caller holding the overwritten grant is refused at redemption and
reruns its flow.

## Unredeemed Grants

A grant that is never redeemed remains in the field until a later flow for that
principal overwrites it. Nothing collects it.

A grant whose holder is lost before redemption, including a result message that
never arrives, leaves a digest no one can produce a preimage for.

## Guessing

The stored value is a digest and the hash is never exposed, so an attacker
searches by presenting candidate grants to the issuer. Each attempt is a network
round trip against a field that is NULL for a given principal most of the time
and that a completed flow overwrites.

The grant carries 256 bits of entropy. The expected number of attempts exceeds
any rate reachable over a network by margins that make the search irrelevant.
