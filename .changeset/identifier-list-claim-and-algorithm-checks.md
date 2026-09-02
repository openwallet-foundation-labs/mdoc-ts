---
'@owf/mdoc': minor
---

Unify MSO revocation list verification (ISO/IEC 18013-5 second edition § 12.3.6) on the typed CWT
structures of `@owf/cose`, and complete it.

The status list and identifier list mechanisms now run the same checks instead of each path checking
a different subset:

- `sub` shall equal the `uri` the list was referenced by, so a list published for one URI can no
  longer be replayed for another under the same trust anchor.
- `exp` shall be present (§ 12.3.6.3) and shall not have passed; `iat` shall be present and not be
  in the future (subject to `checkFreshness`).
- Both comparisons accept a `skewSeconds` tolerance, defaulting to 30 seconds and threaded through
  from `IssuerAuth.verify` like the `ValidityInfo` checks.
- Only `StatusType.Valid` is accepted, per § 12.3.6.1's "no other status besides 'revoked'".

`IdentifierListCwt` is now a `Cwt` subclass built the same way as `StatusListCwt`, rather than a
wrapper that decoded the payload itself:

- `IdentifierListCwtPayload` extends `CwtPayload`, so `subject`, `issuedAt` and `expirationTime` are
  the inherited registered-claim accessors, narrowed to non-optional by the claims schema. Its
  `verifyClaims` layers the § 12.3.6 rules on the generic CWT claim verification, the way
  `StatusListCwtPayload.verifyClaims` layers the Token Status List ones.
- `IdentifierListCwtProtectedHeaders` extends `ProtectedHeaders` with `typ` (16) narrowed to
  `application/identifierlist+cwt`, replacing `IdentifierListCwtHeader` and its hand-rolled schema.
  Headers decoded from a token keep the bytes they were signed over.
- `IdentifierListCwt.verify` checks the signature, the claims and the MSO's identifier in one call,
  mirroring `StatusListCwt.verify`.
- The `StatusList` claim § 12.3.6.4 forbids is rejected by the claims schema rather than by a
  separate check, so the two mechanisms cannot be mixed in one token.

Breaking:

- `IdentifierListCwtHeader` / `IdentifierListCwtHeaderKey` are replaced by
  `IdentifierListCwtProtectedHeaders` and `RegisteredCwtHeaderClaimKey.Typ`.
- `IdentifierListCwt.fromBytes` is `IdentifierListCwt.fromToken`, and an `IdentifierListCwt` is
  constructed with `new IdentifierListCwt({ payload, protectedHeaders })` — `typ` is defaulted.
- `IdentifierListCwt.verifyStatus` takes the `id` only and checks the list membership; the claim
  checks moved to `verifyClaims`.
- `IdentifierListCwtPayload.create` takes a required `uri` (written as `sub`) and `expirationTime`.
- A status list without `exp` or `iat` is now rejected rather than accepted.
- `InvalidAlgorithmError` and `InvalidMessageAuthenticationCode` are removed. Nothing throws them
  any more: the algorithm and MAC failures they reported are now `CoseInvalidSignatureError` from
  `@owf/cose`, mapped onto `InvalidSignatureError`.
- Requires `@owf/cose` 0.4.0 and `@owf/token-status-list` 0.4.0.
