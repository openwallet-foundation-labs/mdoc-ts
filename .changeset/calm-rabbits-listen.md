---
"@owf/mdoc": patch
---

refactor: inline the `getIssuerNameField` / `getPublicKey` signatures in `MdocContext['x509']` instead of indexing into `Sign1Context['x509']`. Decouples `MdocContext` from `@owf/cose`'s internal layout, so the upcoming cose bumps (#197, #198, #200) don't silently drop the parameter types on every downstream `MdocContext` implementation when `Sign1Context['x509']` goes away. Behaviour and shape stay identical.
