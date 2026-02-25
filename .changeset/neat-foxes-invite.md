---
"@owf/mdoc": minor
---

Previously this library copied over the implementation of cbor-x due to React Native incompatiblity issues. With React Native not supporting package exports it can correctly detect the browser build, and we have added back the dependency on the cbor-x library again.
