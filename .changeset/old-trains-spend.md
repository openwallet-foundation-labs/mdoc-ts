---
"@owf/mdoc": minor
---

`trustedCertificates` now has been changed into an array of objects. Where each entry contains `{issuance: Uint8Array[], status?: Uint8Array[]}`. To migrate, use `const newtrustedCertificates = [{issuance: oldTrustedCertificates}]`
