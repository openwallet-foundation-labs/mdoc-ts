---
"@owf/mdoc": minor
---

The library has been rewritten to stay closer to the original encoding of cbor structures, which allows for more deterministic re-encoding, and prevents issues with using e.g. numbers in Maps (will become strings). The biggest change is that the constructor of all cbor structures should not be used anymore, and instead you should call `Class.create`. This will properly handle the transformation from user-facing options into the CBOR structure. The constructor is also used for decoding from different formats (e.g. after cborDecode, after validation, etc..), so you SHOULD NOT use these directly as it bypasses validation.

The output of created mDOCs might be slightly different, but parsing has been implemented with some backwards compatibility in mind to ensure interoperability with 0.5 of this library. Due to the improved validation, there is stricter checking whether the CBOR matches the COSE and mDOC specification. This might cause small issues with other implementations, but the test vectors in this repository compare against several other implementations. Please raise issues if you do encounter any issues.