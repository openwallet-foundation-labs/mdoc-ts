# @owf/mdoc

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
