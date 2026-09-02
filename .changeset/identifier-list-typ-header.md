---
'@owf/mdoc': patch
---

Require the identifier list CWT's `typ` in the COSE protected header (RFC 9596 label 16) instead of as a CWT payload claim. Verification of an mdoc whose MSO carries an `identifierList` status previously failed with `Expected key '16' to be defined` against every issuer that follows the spec, since `typ` is a header parameter — the same place `@owf/token-status-list` writes it on a status list CWT. It is checked before the payload is decoded, so a token of another media type is rejected as such.

Adds `IdentifierListCwtHeader`, a typed structure for the CWT's protected header (`alg`, `x5chain`, `typ`) alongside the existing `IdentifierListCwtPayload`.
