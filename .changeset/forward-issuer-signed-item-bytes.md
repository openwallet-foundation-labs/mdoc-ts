---
"@owf/mdoc": patch
---

Forward the issuer's own `IssuerSignedItemBytes` when presenting a credential, instead of re-encoding each item from its decoded structure. A verifier digests the bytes it receives and compares them to `valueDigests`, so re-encoding made genuine claims from other CBOR encoders fail at the verifier.
