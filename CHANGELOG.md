# @owf/mdoc

## 0.7.0

### Minor Changes

- 97425f2: Updated MdocContext.mac.sign to MdocContext.mac.authenticate
- 21abd59: refactor: only allow CoseKey for sign1.verify callback
- 4a684ee: Return the `documents`, `trustedIssuanceChains`, `trustedStatusListChains`, `trustedIdentifierListChains`, `statusLists` and `identifierLists` to the user after calling verify.
- 982e9c7: fix: correctly handle detached payload vs payload on sign1 and mac0. The detached payload is not available on the Sign1 and Mac0 classes anymore, and should be provided to the method classes directly. Detached payload cannot be provided anymore when embedded payload is already present. The `mac0` and `sign1` structures are not passed anymore to the context, but the already encoded data is provided.
- 6e82f06: `trustedCertificates` now has been changed into an array of objects. Where each entry contains `{issuance: Uint8Array[], status?: Uint8Array[]}`. To migrate, use `const newtrustedCertificates = [{issuance: oldTrustedCertificates}]`
- 9008cf5: feat: implement identifier-list revocation (ISO 18013-5 2nd ed § 12.3.6).

  - Adds `IdentifierList`, `IdentifierListCwtPayload`, `IdentifierListCwt` modelling the spec's CDDL with `CborStructure` + `typedMap` schemas. `IdentifierList` carries `identifiers: { Identifier => IdentifierInfo }` with optional `aggregation_uri` and RFU keys. `includes()` uses `compareBytes` from `@owf/identity-common`.
  - New enums: `IdentifierListCwtClaimKey` (claim 65530), `CwtClaimKey` (Typ = 16, RFC 9596), `MediaTypes` (IdentifierListCwt = "application/identifierlist+cwt").
  - `IdentifierListCwt` wraps `@owf/cose`'s `Cwt`; `verifySignature` delegates to `cwt.asSign1.verifySignature`. `fromBytes` enforces § 12.3.6.4: `StatusList` claim must be absent; `typ` claim must equal `application/identifierlist+cwt`; payload schema requires `exp`.
  - Wires the identifier-list path into `IssuerAuth.verifyStatus` alongside the existing status-list path. When the MSO carries both mechanisms, both are verified. The identifier-list branch extracts the x5chain from the CWT's protected header, validates the chain against `trustedStatusCertificates`, derives the public key via `ctx.x509.getPublicKey`, verifies the signature via `ctx.cose.sign1.verify`, and throws when the identifier appears in the list. New error types: `UnableToExtractX5ChainFromIdentifierListError`, `InvalidIdentifierListSignatureError`.
  - `IssuerAuth.verifyStatus` now returns `Promise<void>` (was `Promise<Uint8Array | undefined>`) — the matched-cert concept doesn't carry meaning for the status / identifier list paths the way it does for the mdoc issuer chain. `IssuerAuth.verify` / `IssuerSigned.verify` / `Holder.verify` / `DeviceResponse.verify` drop `trustedStatusCertificate` from their return values for the same reason. Returning the full verified chain for audit / compliance is left as a future enhancement.

- d09d284: feat: add `IsoMdocDcApiHandover` for the ISO 18013-7 Annex C `org-iso-mdoc` DC API protocol, with a `SessionTranscript.forIsoMdocDcApi` factory. Shape: `[ "dcapi", SHA-256(CBOR([encInfoB64u, origin])) ]`. Distinct from the OpenID4VP DC API handover; needed when verifying responses from a wallet that answered an `org-iso-mdoc` request (the only protocol Safari on iOS 26 supports).
- 21abd59: only allow CoseKey as return value for getPublicKey

### Patch Changes

- cde2491: Fix `deviceSignature` emitting a malformed `kid` header (`{ 4: undefined }`) when the device signing key has no `keyId`. `DeviceResponse.create` now only sets the `kid` unprotected header when a `keyId` is present, matching `DeviceSignedBuilder`.
- 6dc5052: Constrain generated `DigestID` values to `[0, 2^31 - 1]` as mandated by ISO/IEC 18013-5 §12.3.4. `randomUnsignedInteger` previously used `>>> 0`, producing values in `[0, 2^32 - 1]`; the most significant bit is now masked off so parsers that deserialize `digestID` into a signed/u31 range no longer fail with a CBOR decoding error.
- 5f0b6b6: feat: add support for Node 26
- d22e526: - Check signature on CWT status list, jwt is not checked yet.
  - Allow to pass in `trustedRevocationCertificates` to verify the leaf cert for the status list
  - X5Chain is now added to the protectedheaders instead of the unprotectedheaders
- f1cd55f: fix: resolve bug in selecting status cert based on issuance cert
- d0575f0: Bump `@owf/cose`, `@owf/identity-common`, and `@owf/token-status-list` to `0.3.0-alpha-20260605053037`, and encode the COSE `kid` header (label 4) as a byte string per RFC 8152. The new `@owf/cose` typed-header schema rejects the text-string form previously emitted; bytes was always the spec-compliant encoding.
- cfbf104: chore: update to stable 0.3.x versions of @owf libraries

## 0.6.0

### Minor Changes

- f79518c: feat: support more than one certificate in the certificate chain when signing an mdoc. The `certificate` parameter has been renamed to `certificates` and now expects an array with at least one certificate.
- 153111e: - Major rework of the library, primairly the underlying CBOR structures
  - Includes an `Issuer`, `Holder` and `Verifier` class that should make it easier to issue, hold and verify mDocs
  - More aligned with the specification, w.r.t. naming conventions
  - Simplified additions/modifitcations, so adding newer features will be a lot simpler
- fd7cc00: feat: add new openid4vp session transcript calculation methods.

  NOTE that this introduces breaking chnages since `calculateSessionTranscriptBytesForOid4VpDcApi` has been renamed to `calculateSessionTranscriptBytesForOid4VpDcApiDraft24`. The `calculateSessionTranscriptBytesForOid4VpDcApi` method is now used for the latest (draft29/1.0) session transcript structure.

  In addtion, `calculateSessionTranscriptBytesForOid4Vp` has been renamed to `calculateSessionTranscriptBytesForOid4VpDraft18`. The `calculateSessionTranscriptBytesForOid4Vp` method is now used for the latest (draft29/1.0) session transcript structure.

- 2d5163f: The library has been rewritten to stay closer to the original encoding of cbor structures, which allows for more deterministic re-encoding, and prevents issues with using e.g. numbers in Maps (will become strings). The biggest change is that the constructor of all cbor structures should not be used anymore, and instead you should call `Class.create`. This will properly handle the transformation from user-facing options into the CBOR structure. The constructor is also used for decoding from different formats (e.g. after cborDecode, after validation, etc..), so you SHOULD NOT use these directly as it bypasses validation.

  The output of created mDOCs might be slightly different, but parsing has been implemented with some backwards compatibility in mind to ensure interoperability with 0.5 of this library. Due to the improved validation, there is stricter checking whether the CBOR matches the COSE and mDOC specification. This might cause small issues with other implementations, but the test vectors in this repository compare against several other implementations. Please raise issues if you do encounter any issues.

- 2d5163f: Previously this library copied over the implementation of cbor-x due to React Native incompatiblity issues. With React Native not supporting package exports it can correctly detect the browser build, and we have added back the dependency on the cbor-x library again.
- 0311619: fix: use variable map size for map encoding
- 6c2f153: feat: add a confirable (default 30 seconds) skew for verification of signatures. Especially mobile devices can have some time drift, meaning that a just-issued credential fails verification.
- 15a8efa: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason mDOC is now fully an ESM module.

### Patch Changes

- 001b494: - Export the method to limit the disclosures so it can be used by the user without requiring them to set/create a signature
- 2963990: feat: native JS implementation of byte encoding and decoding
- 42b78f8: fix: in the rewrite of 0.5 to 0.6 the issuer sigend item was changed from a map to an object, and the order of the issuer signed item from signed mdoc was not retained anymore. this resulted in errors saying the digest could not be found. The issuer signed item is now correctly encoded as map again, and the order has been fixed to match the ISO 18013-5 specification
- 52d5515: feat: add SessionTranscript for OpenID4VP with Interactive Authorization (OpenID4VCI presentation during issuance)
- 8aba197: Added the SignatureAlgorithm to the Sign1 callback in the context as it is not always defined on the key
- c924f2f: fix: encoding of COSE Keys. An object was used which means the COSE keys were encoded as strings and not numbers
- 3f19ace: fix: always true statement throws error. In the DeviceResponse model there was an always true if statement that throws an error before allowing the creation of the response.
- 3f82155: Fix proximity SessionTranscript by passing rawBytes directly

## 0.5.2

### Patch Changes

- b8c2ad6: feat: support `optional` keyword in PEX input descriptor field

## 0.5.1

### Patch Changes

- 8d7a541: fix: do not include undefined 'expectedUpdate'

## 0.5.0

### Minor Changes

- 4ce7385: rename calculateSessionTranscript methods to calculateSessionTranscriptBytes as they are different things and the bytes are returned
- 04dd7d8: fix: DateOnly does not extend Date anymore as it would lead to issues with instanceof checks

### Patch Changes

- 5b708d2: fix: x5c header as string not array because there's only one certificate according to RFC 9360 (https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1)

## 0.4.1

### Patch Changes

- 34152fd: fix: do not include "undefined" for deviceMac if not used in device response
- 34152fd: fix: update context interface to not allow random callback to be async

  The current code did not await the callback, and thus did not support async random generation. In a future (breaking) change we might update the code to support async random byte generation, but most random byte generators in JavaScript are sync. If you depend on an async random byte generator, please open an issue.

## 0.4.0

### Minor Changes

- 59e3266: fix: do not include age_over_NN attributes by default
- e54a767: - Remove magic surrounding the date type, this means that when you provide the input for an mdl, make sure that the `birth_date`, `driving_privileges[n].issue_date` and `driving_privileges[n].expiry_date` are of class `DateOnly` and `issue_date` and `expiry_date` are of type `Date`.

### Patch Changes

- 4187667: feat: add OID4VP DC API session transcript calculation
- ff41f06: Include different age*over_NN values and exclude age_over*<CURRENT_AGE>

## 0.3.0

### Minor Changes

- 65fcc93: feat: support ISO 18013-7 Draft 2024-03-12.

  This mostly changes the structure of the calculated session transcript bytes for usage with the Web API or OpenID4VP. This is a breaking change and incompatible with older versions of this library.

## 0.2.39

### Patch Changes

- d3cee49: fix: use null for payload instead of undefined
- d3cee49: fix: correctly handle map vs object

## 0.2.38

### Patch Changes

- 9df25d9: build: publish dist

## 0.2.37

### Patch Changes

- 43becf8: refactor: restructure repo
