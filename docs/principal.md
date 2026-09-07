# Principal Service

## Scope

This document is the authority for the principal record and the operations the
Principal service exposes. [Register](./register.md) defines when a principal is
created and what commits alongside it. [Grant](./grant.md) defines the value
stored in `grantHash` and the rules the service applies when checking it.

A principal is an identity that a token's `sub` claim names. The service owns
the record and is the only writer of `grantHash` after the record exists.

## Record

```text
principalId
name
displayName
creationDate
lastAuthenticatedDate
grantHash
```

`principalId` is opaque and carries no personally identifying information. Its
constraints and generation are defined by
[Register](./register.md#publickeycredentialcreationoptions).

`name` and `displayName` hold the values defined by
[Register](./register.md#registerstart).

`creationDate` is the UNIX timestamp at which the flow created the record.
`lastAuthenticatedDate` is the UNIX timestamp of the most recent flow that
authenticated the principal. [Register](./register.md#atomic-persistence) writes
one timestamp to both fields, and [Login](./login.md#policy-evaluation) advances
`lastAuthenticatedDate`.

`grantHash` holds the digest of the principal's outstanding grant, or NULL when
none is outstanding.

## Creation

No RPC creates a principal. Creation belongs to the flow that establishes the
subject as legitimate, and happens inside that flow's atomic commit.
[Register](./register.md#atomic-persistence) is one such flow, committing the
principal, the credential record, and `grantHash` together.

A flow that mints tokens for a principal it creates commits the principal the
same way. A principal that exists is one some flow already decided was
legitimate, so no separate authorization step guards its creation.

## GetGrantHash

```text
GetGrantHash(principalId) → grantHash
```

The service answers with the value stored in that principal's `grantHash`, or
with NULL when none is outstanding. It refuses when no record exists for
`principalId`.

The service performs no comparison. Whoever mints a token performs it, for the
reason [Redemption](./grant.md#redemption) gives.

Answering costs nothing. A hash yields nothing without the grant that produced
it, and only a grant passes the comparison.

## ClearGrant

```text
ClearGrant(principalId, grant) → cleared or refused
```

The service computes the digest of the presented grant and clears the
principal's `grantHash` to NULL, conditional on the stored value still equalling
that digest. It refuses when no record exists, when the stored value is NULL,
and when the stored value differs from the computed digest.

The method takes the grant rather than its digest so that clearing requires what
minting requires. A caller holding only the value `GetGrantHash` answers with
destroys nothing.

The conditional is what makes a grant single-use, and it holds against a grant
written between another caller's read and its clear.

The comparison here gates the clear. It establishes nothing about which subject
a token names, which is why the issuer performs its own, as
[Redemption](./grant.md#redemption) defines.

Both methods are publicly reachable. Neither answers usefully to a caller
without the grant.

## DeletePrincipal

```text
DeletePrincipal(token) → ()
```

The caller presents a token. The service verifies it through
[Token Verifier](./token-verifier.md) and deletes the principal its `sub` names.
A caller deletes only the principal it holds a token for.

The delete cascades to every credential record referencing that principal, and
the principal and those records are removed in one atomic operation.
[Register](./register.md#atomic-persistence) makes the credential record's
reference to the principal a stored constraint, so a delete that removed the
principal alone would leave that constraint unsatisfied.

The service refuses a token that fails verification.
