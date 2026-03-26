# @owf/mdoc

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
