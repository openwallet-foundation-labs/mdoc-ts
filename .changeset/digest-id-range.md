---
"@owf/mdoc": patch
---

Constrain generated `DigestID` values to `[0, 2^31 - 1]` as mandated by ISO/IEC 18013-5 §12.3.4. `randomUnsignedInteger` previously used `>>> 0`, producing values in `[0, 2^32 - 1]`; the most significant bit is now masked off so parsers that deserialize `digestID` into a signed/u31 range no longer fail with a CBOR decoding error.
