---
"@owf/mdoc": patch
---

fix: in the rewrite of 0.5 to 0.6 the issuer sigend item was changed from a map to an object, and the order of the issuer signed item from signed mdoc was not retained anymore. this resulted in errors saying the digest could not be found. The issuer signed item is now correctly encoded as map again, and the order has been fixed to match the ISO 18013-5 specification
