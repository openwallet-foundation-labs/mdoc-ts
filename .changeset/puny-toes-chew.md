---
"@owf/mdoc": patch
---

- Check signature on CWT status list, jwt is not checked yet.
- Allow to pass in `trustedRevocationCertificates` to verify the leaf cert for the status list
- X5Chain is now added to the protectedheaders instead of the unprotectedheaders
