---
"@owf/mdoc": patch
---

Verify `IssuerSignedItem` digests over the received tag-24 bytes instead of a re-encode, so credentials from other CBOR encoders still pass `isValid`.
