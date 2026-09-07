# Token Verifier

## Scope

This document is the authority for the Token Verifier service: the key it holds,
what it checks, and what it answers with.

## Responsibilities

The service holds the public key matching the signing key held by
[Token Issuer](./token-issuer.md). It holds no signing key and produces no
tokens.

The service reads and writes no store and keeps no state between requests. Its
answer depends on the token presented, the public key it holds, and the clock.

## DecodeToken

```text
DecodeToken(token) → claims
```

The service verifies the token's signature against the public key it holds, then
checks `exp` and `nbf` against the current time. A token carrying no `exp` claim
does not expire and passes that check.

The service verifies using the algorithm its configuration supplies alongside
the public key. It does not read the token header's `alg`. The header is covered
by the signature, so a token whose header was altered fails verification against
the configured algorithm.

On success the service answers with the claims the token carries, unaltered.

## Audience

The service enforces nothing about `aud` and answers with the value the token
carries.

A consumer knows which audience names it and the service does not, so the
consumer compares. Enforcing it here would require every consumer to declare its
own identity to this service, and a consumer able to declare it can compare the
value itself.

## Exposure

The service is publicly reachable. A caller presenting a token already holds it,
and the answer describes only that token.

Verification requires the public key alone, so the service is deployed and
scaled without reference to how many tokens are minted.

## Refusals

The service refuses a malformed token, a signature that does not verify, an
expired token, and a token whose `nbf` has not arrived. It reports which.

A refused token yields no claims. The service exposes no method that returns
claims without performing these checks.
