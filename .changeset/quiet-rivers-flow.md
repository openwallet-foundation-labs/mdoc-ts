---
"@owf/mdoc": minor
---

feat: implement identifier-list revocation (ISO 18013-5 2nd ed § 12.3.6).

- Adds `IdentifierList`, `IdentifierListCwtPayload`, `IdentifierListCwt` modelling the spec's CDDL with `CborStructure` + `typedMap` schemas. `IdentifierList` carries `identifiers: { Identifier => IdentifierInfo }` with optional `aggregation_uri` and RFU keys. `includes()` uses `compareBytes` from `@owf/identity-common`.
- New enums: `IdentifierListCwtClaimKey` (claim 65530), `CwtClaimKey` (Typ = 16, RFC 9596), `MediaTypes` (IdentifierListCwt = "application/identifierlist+cwt").
- `IdentifierListCwt` wraps `@owf/cose`'s `Cwt`; `verifySignature` delegates to `cwt.asSign1.verifySignature`. `fromBytes` enforces § 12.3.6.4: `StatusList` claim must be absent; `typ` claim must equal `application/identifierlist+cwt`; payload schema requires `exp`.
- Wires the identifier-list path into `IssuerAuth.verifyStatus` alongside the existing status-list path. When the MSO carries both mechanisms, both are verified. The identifier-list branch extracts the x5chain from the CWT's protected header, validates the chain against `trustedStatusCertificates`, derives the public key via `ctx.x509.getPublicKey`, verifies the signature via `ctx.cose.sign1.verify`, and throws when the identifier appears in the list. New error types: `UnableToExtractX5ChainFromIdentifierListError`, `InvalidIdentifierListSignatureError`.
- `IssuerAuth.verifyStatus` now returns `Promise<void>` (was `Promise<Uint8Array | undefined>`) — the matched-cert concept doesn't carry meaning for the status / identifier list paths the way it does for the mdoc issuer chain. `IssuerAuth.verify` / `IssuerSigned.verify` / `Holder.verify` / `DeviceResponse.verify` drop `trustedStatusCertificate` from their return values for the same reason. Returning the full verified chain for audit / compliance is left as a future enhancement.
