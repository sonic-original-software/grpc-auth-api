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

The service computes the SHA-256 digest of the presented grant. It then requests
one compare-and-swap, which the store performs as a single atomic operation
carrying out these steps in order:

```text
read the stored grantHash
compare it to the computed digest
write NULL when the two are equal, and write nothing when they differ
```

No other writer reads or changes `grantHash` between those steps. A store that
performed the read and the write as separate operations would leave a window in
which another writer could replace the value the comparison approved.

The atomic operation reports whether it wrote, and `ClearGrant` answers with that
report.

The service refuses when no record exists, when the stored value is NULL, or when
the atomic operation reports that it did not write.

The method takes the grant rather than its digest because
[GetGrantHash](#getgranthash) answers any caller. Accepting a digest would let a
caller read a principal's digest and clear the grant that produced it.

The compare-and-swap is what makes a grant single-use. A swap that writes nothing
means another flow wrote a new grant after this caller read the field, and that
new grant survives for the holder it was issued to.

Both methods are publicly reachable. Neither answers usefully to a caller
without the grant.

## DeletePrincipal

```text
DeletePrincipal(principalId) → ()
```

The service deletes the principal named by `principalId`.

Every request carries an authenticated requester, established before it reaches
this service. The service acts on that requester's authority and refuses a
request carrying none, or one whose requester is not authorized to delete the
named principal. The named principal is the requester or any other principal
that authorization covers.

The delete cascades to every credential record referencing that principal, and
the principal and those records are removed in one atomic operation.
[Register](./register.md#atomic-persistence) makes the credential record's
reference to the principal a stored constraint, so a delete that removed the
principal alone would leave that constraint unsatisfied.

The service refuses a request naming a principal with no record.
