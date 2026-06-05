---
"@owf/mdoc": patch
---

Bump `@owf/cose`, `@owf/identity-common`, and `@owf/token-status-list` to `0.3.0-alpha-20260605053037`, and encode the COSE `kid` header (label 4) as a byte string per RFC 8152. The new `@owf/cose` typed-header schema rejects the text-string form previously emitted; bytes was always the spec-compliant encoding.
