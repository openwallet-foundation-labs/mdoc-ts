---
"@owf/mdoc": patch
---

Fix `deviceSignature` emitting a malformed `kid` header (`{ 4: undefined }`) when the device signing key has no `keyId`. `DeviceResponse.create` now only sets the `kid` unprotected header when a `keyId` is present, matching `DeviceSignedBuilder`.
