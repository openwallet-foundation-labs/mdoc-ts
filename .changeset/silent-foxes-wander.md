---
"@owf/mdoc": minor
---

feat: add `IsoMdocDcApiHandover` for the ISO 18013-7 Annex C `org-iso-mdoc` DC API protocol, with a `SessionTranscript.forIsoMdocDcApi` factory. Shape: `[ "dcapi", SHA-256(CBOR([encInfoB64u, origin])) ]`. Distinct from the OpenID4VP DC API handover; needed when verifying responses from a wallet that answered an `org-iso-mdoc` request (the only protocol Safari on iOS 26 supports).
