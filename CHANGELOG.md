# @owf/mdoc

## 0.8.0

### Minor Changes

- 740b4e1: Enforce the `age_over_NN` limit of ISO/IEC 18013-5 7.2.5, "an mDL reader shall not request more than two age_over_NN data elements", counted per namespace:

  - `ItemsRequest.create`, and therefore `IsoMdocDcApi.createRequest`, throws an `AgeOverLimitExceededError` when more than two are requested in a namespace. A decoded request is not checked, so that a holder can report it.
  - `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` report the limit through the verification callback, so with the default callback a request for more than two throws a `VerificationError`.
  - `Holder.matchDeviceRequest` does not match any credential against a doc request for more than two. The doc request fails with `invalidDocRequest: { failure: 'ageOverLimitExceeded', reason }` and empty `failedCredentials`.
  - `DeviceResponse.createWithDeviceRequest` throws an `AgeOverLimitExceededError` when a document would disclose more than two distinct age attestations in a namespace. Only what is disclosed counts, so a holder can still answer such a request by selecting at most two of them through `elements`.

- aa67c35: Add ISO/IEC TS 18013-7:2025 Annex C (`org-iso-mdoc`) DC API support: `EncryptionInfo`,
  `EncryptionParameters`, `EncryptedResponse` and `EncryptedResponseData` models, optional
  `crypto.hpke` context callbacks, and an `IsoMdocDcApi` API to create/parse requests and
  create/decrypt/verify encrypted responses.
- 63f630c: Add four ISO/IEC 18013-5 conformance checks that verification was missing. All four are reported through the existing `onCheck` callback, so `defaultVerificationCallback` now throws on responses that previously passed:

  - **Key authorizations (9.1.3.4).** An mdoc "shall only authenticate response data elements in `DeviceNameSpaces` if the key it is using for mdoc authentication is authorized to authenticate these elements in the `KeyAuthorizations` structure in the MSO", and "the mdoc reader shall validate this authorization as part of validating the mdoc authentication". Creating a response only discloses requested device-signed elements the MSO authorizes, including when it has no `keyAuthorizations` at all: a requested element that can only be answered with an unauthorized value throws a `MissingRequestedElementError`, and unrequested values in `deviceNamespaces` are left out.
  - **Response status (8.3.2.1.2.3, Table 8).** "If the mdoc returns a status code different from 0, it shall not return any documents".
  - **Duplicate element identifiers (8.3.2.1.2.2).** "The mdoc shall not include two or more `IssuerSignedItem` elements with the same `DataElementIdentifier` in a single `NameSpace` and `Document`".
  - **Document docType (9.3.1).** The mdoc reader shall "verify that the DocType in the MSO matches the relevant DocType in the Documents structure". This was only checked when a `deviceRequest` was passed to `DeviceResponse.verify`, and is now checked for every document.

- 740b4e1: `DeviceResponse.createWithDeviceRequest` and `IsoMdocDcApi.createResponse` select the elements to disclose the same way `Holder.matchDeviceRequest` matches a credential:

  - A requested element the issuer did not sign, but that the device key is authorized for, is disclosed through the `deviceNamespaces` of the document. Before, every requested element had to be issuer-signed.
  - A document can pass `elements` to disclose only some of the requested elements, for instance leaving out the ones the user declined to share. This applies to issuer-signed and device-signed elements alike: only the values in `deviceNamespaces` of selected requested elements are disclosed and authenticated.
  - A requested element that cannot be disclosed throws a `MissingRequestedElementError`, and selecting an element the doc request does not ask for throws an `InvalidElementSelectionError`.
  - Two `age_over_NN` requests answered with the same age attestation (18013-5 7.2.5) have to be selected together or left out together, as leaving out only one would still disclose its answer. Selecting only one throws an `InvalidElementSelectionError`. `disclosedElementIdentifier` on the claims of `Holder.matchDeviceRequest` shows which requests share an attestation.
  - A credential whose MSO docType is not the docType of the doc request it answers throws a `DocTypeMismatchError`, instead of producing a document every reader rejects.

  `limitDisclosureToDeviceRequestNameSpaces` is removed. Use `DeviceResponse.createWithDeviceRequest`, with `elements` to disclose a subset of the requested elements.

- aa67c35: `DeviceResponse.createWithDeviceRequest` now takes a `documents` array instead of a single
  `issuerSigned` list with one shared device key, so a response can disclose several documents that
  each bring their own device key and device namespaces. Every document names the doc request it
  answers through `docRequestIndex`, so a request may also be answered partially.
  `Holder.createDeviceResponseForDeviceRequest` takes the same options.

  ```ts
  await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest,
      sessionTranscript,
      documents: [
        { issuerSigned, docRequestIndex: 0, signature: { signingKey } },
      ],
    },
    ctx
  );
  ```

- 63f630c: **Breaking:** `DeviceResponse.verify`, `Verifier.verifyDeviceResponse` and `IsoMdocDcApi.verifyResponse` (as `verificationResult`) now return an object instead of an array. The per document results moved to `documents`:

  ```ts
  // before
  const results = await deviceResponse.verify(options, ctx);

  // after
  const { documents } = await deviceResponse.verify(options, ctx);
  ```

- 7f7b939: Remove the `certificate` option of `DeviceSignedBuilder.sign` and `DeviceSignedBuilder.tag`. The device signature and device MAC of ISO/IEC 18013-5 9.1.3 are verified with the device key in the `deviceKeyInfo` of the MSO, so an `x5chain` header on the device auth has no meaning. The builder no longer adds one, like `DeviceResponse.createWithDeviceRequest` already did.
- 63f630c: `Document.errors` is now always an `Errors` instance. `DocumentOptions.errors` takes an `Errors` instead of a `Map<Namespace, ErrorItems>`:

  ```ts
  Document.create({
    docType,
    issuerSigned,
    deviceSigned,
    errors: Errors.create({
      errors: new Map([
        [
          namespace,
          ErrorItems.create({ errorItems: new Map([["birth_date", 0]]) }),
        ],
      ]),
    }),
  });
  ```

  `Errors` gains `errors`, `getErrorItems(namespace)` and `create`, and `ErrorItems` gains `errorItems`
  and `getErrorCode(dataElementIdentifier)`.

- 337c841: Unify MSO revocation list verification (ISO/IEC 18013-5 second edition § 12.3.6) on the typed CWT
  structures of `@owf/cose`, and complete it.

  The status list and identifier list mechanisms now run the same checks instead of each path checking
  a different subset:

  - `sub` shall equal the `uri` the list was referenced by, so a list published for one URI can no
    longer be replayed for another under the same trust anchor.
  - `exp` shall be present (§ 12.3.6.3) and shall not have passed; `iat` shall be present and not be
    in the future (subject to `checkFreshness`).
  - Both comparisons accept a `skewSeconds` tolerance, defaulting to 30 seconds and threaded through
    from `IssuerAuth.verify` like the `ValidityInfo` checks.
  - Only `StatusType.Valid` is accepted, per § 12.3.6.1's "no other status besides 'revoked'".

  `IdentifierListCwt` is now a `Cwt` subclass built the same way as `StatusListCwt`, rather than a
  wrapper that decoded the payload itself:

  - `IdentifierListCwtPayload` extends `CwtPayload`, so `subject`, `issuedAt` and `expirationTime` are
    the inherited registered-claim accessors, narrowed to non-optional by the claims schema. Its
    `verifyClaims` layers the § 12.3.6 rules on the generic CWT claim verification, the way
    `StatusListCwtPayload.verifyClaims` layers the Token Status List ones.
  - `IdentifierListCwtProtectedHeaders` extends `ProtectedHeaders` with `typ` (16) narrowed to
    `application/identifierlist+cwt`, replacing `IdentifierListCwtHeader` and its hand-rolled schema.
    Headers decoded from a token keep the bytes they were signed over.
  - `IdentifierListCwt.verify` checks the signature, the claims and the MSO's identifier in one call,
    mirroring `StatusListCwt.verify`.
  - The `StatusList` claim § 12.3.6.4 forbids is rejected by the claims schema rather than by a
    separate check, so the two mechanisms cannot be mixed in one token.

  Breaking:

  - `IdentifierListCwtHeader` / `IdentifierListCwtHeaderKey` are replaced by
    `IdentifierListCwtProtectedHeaders` and `RegisteredCwtHeaderClaimKey.Typ`.
  - `IdentifierListCwt.fromBytes` is `IdentifierListCwt.fromToken`, and an `IdentifierListCwt` is
    constructed with `new IdentifierListCwt({ payload, protectedHeaders })` — `typ` is defaulted.
  - `IdentifierListCwt.verifyStatus` takes the `id` only and checks the list membership; the claim
    checks moved to `verifyClaims`.
  - `IdentifierListCwtPayload.create` takes a required `uri` (written as `sub`) and `expirationTime`.
  - A status list without `exp` or `iat` is now rejected rather than accepted.
  - `InvalidAlgorithmError` and `InvalidMessageAuthenticationCode` are removed. Nothing throws them
    any more: the algorithm and MAC failures they reported are now `CoseInvalidSignatureError` from
    `@owf/cose`, mapped onto `InvalidSignatureError`.
  - Requires `@owf/cose` 0.4.0 and `@owf/token-status-list` 0.4.0.

- 7f7b939: Fix the issuer checks against the document signer certificate (ISO/IEC 18013-5 7.2.1, 9.3.1):

  - `issuing_country` and `issuing_jurisdiction` are compared with the `countryName` and `stateOrProvinceName` in the subject of the document signer certificate, instead of in its issuer. **Breaking:** the `x509.getIssuerNameField` context callback is replaced by `x509.getSubjectNameField`, which returns the fields of the subject distinguished name.
  - `issuing_jurisdiction` is only checked when the document signer certificate has a `stateOrProvinceName`, as the check "is only required if the stateOrProvinceName element is present in the DS certificate". Before, it FAILED for every certificate without one.
  - With `disableCertificateChainValidation`, verification no longer reports a FAILED `Unable to determine a trusted issuance chain` check, so `defaultVerificationCallback` no longer throws. The certificate chain of a status list or identifier list is then not validated either: the list is verified with the key of the leaf of its x5chain, and the revocation status is still checked. Before, verifying a credential with a status always FAILED without chain validation, as there were no trusted status certificates. `IssuerAuth.verifyStatus`, `verifyStatusListToken` and `verifyIdentifierListToken` accept `disableCertificateChainValidation` for the same, and then return no `chain`.

- 7f7b939: `Issuer` and `IssuerSignedBuilder` refuse to create a credential that does not conform to ISO/IEC 18013-5:

  - Signing throws an `InvalidValidityInfoError` when `validFrom` is before `signed`, or when `validUntil` is not later than `validFrom` (9.1.2.4).
  - Adding an element identifier that is already in the namespace throws a `DuplicateElementIdentifierError` (8.3.2.1.2.2). Before, both elements were added.
  - Adding an element throws when its random digest ID is already used in the namespace. Before, the digest of the first element was silently replaced in the MSO.

- 63f630c: Add `Verifier.matchDeviceRequest` and `Holder.matchDeviceRequest` to match a `DeviceRequest`. The verifier checks whether a `DeviceResponse` satisfies it, and the holder selects which credentials can answer which doc request. Both share the same matching and return the same nested result, so it shows what failed and not just that something failed:

  - Per doc request: `success`, and the valid and failed documents (`validDocuments` and `failedDocuments`) or credentials (`validCredentials` and `failedCredentials`).
  - Per document or credential: `success`, a `docType` check and a `claims` check.
  - The `claims` check: `validClaims` and `failedClaims` per requested element (with which `age_over_NN` answered an age request), and for a document the `unrequestedClaims` it disclosed without being asked for them.

  Every level is a union on `success`, so checking `success` narrows everything below it: when `match.success` is `true` (and `match.docRequestsAsAlternatives` is `false`), every doc request has at least one valid document or credential, and its checks are successful.

  A device request with more than one doc request does not say whether it asks for all of them or for any one of them. By default every doc request has to be satisfied. Set `treatAmbiguousMultipleDocRequestsAsAlternatives: true` (in `matchOptions` for the verifier, top-level for `Holder.matchDeviceRequest`) to treat them as alternatives of which at least one has to be satisfied, a common interpretation until use cases from the second edition of 18013-5 are supported. The result's `docRequestsAsAlternatives` says which way it was matched, and verification then reports a single check for the alternatives instead of one per doc request.

  A requested element can be answered issuer-signed, or device-signed when the device key is authorized for it in the MSO. A holder passes a credential as `{ issuerSigned, deviceNamespaces }` to provide the values it can disclose device-signed, and a credential only matches when `DeviceResponse.createWithDeviceRequest` can answer the doc request with the same `deviceNamespaces`. The holder matches as if every element may come from either source. The verifier only accepts issuer-signed elements and requires every element by default. Use `matchOptions` to mark elements optional or allow them from `deviceSigned`, per doc request by `docRequestIndex`:

  ```ts
  const match = Verifier.matchDeviceRequest({
    deviceRequest,
    deviceResponse,
    matchOptions: {
      docRequests: [
        {
          docRequestIndex: 0,
          elements: {
            "org.iso.18013.5.1": { portrait: { optional: true } },
            // '*' applies to every element in the namespace
            "com.example.device": { "*": { source: "deviceSigned" } },
          },
        },
      ],
    },
  });
  ```

  `DeviceResponse.verify`, `Verifier.verifyDeviceResponse` and `IsoMdocDcApi.verifyResponse` run the same match when you pass a `deviceRequest`, with the options in `deviceRequestMatchOptions` and the result in `deviceRequestMatch`. A failed match lists every missing element instead of stopping at the first one, and throws a `VerificationError` (which still extends `MdlError`) with the match attached as `error.assessment.result.match`. Match options that do not fit the device request throw an `InvalidDeviceRequestMatchOptionsError` before anything is verified. Elements a document disclosed that no doc request of its docType asked for are reported once per document as a `WARNING`.

- 740b4e1: `IssuerSigned` now decodes and encodes without `nameSpaces`, so `IssuerSigned.issuerNamespaces` can be `undefined`. 18013-5 requires `IssuerNameSpaces` to have at least one namespace, so when `DeviceResponse.createWithDeviceRequest` discloses no issuer-signed element, `issuerSigned.nameSpaces` is left out instead of encoded as an empty map.
- 7f7b939: **Breaking:** `trustedIssuanceChain` in the results of `IssuerAuth.verify`, `IssuerSigned.verify` and `DeviceResponse.verify` is now typed as optional. It was already undefined at runtime when `disableCertificateChainValidation` is set, or when chain validation failed with a verification callback that does not throw, but the type claimed it was always an array.
- 740b4e1: Reader auth certificate chain validation is no longer skipped silently. `ReaderAuth.verify`, `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` now report a FAILED `Reader certificate chain must be trusted` check when a doc request carries reader auth but no trusted reader certificates are provided, so `defaultVerificationCallback` throws. Before, only the signature was verified, and any self-signed reader certificate was accepted.

  To only verify the signature, pass `disableCertificateChainValidation: true` to `ReaderAuth.verify` and `Holder.verifyDeviceRequest`, or `disableReaderCertificateChainValidation: true` to `IsoMdocDcApi.parseRequest`.

- 7f7b939: Embedded structures that are signed, MACed or hashed (`ItemsRequestBytes`, `DeviceNameSpacesBytes`, `DeviceEngagementBytes`, `EReaderKeyBytes`, `IssuerSignedItemBytes`) are now used with the bytes they were received as, as ISO/IEC 18013-5 8.1 requires, instead of being re-encoded. This fixes reader auth and device auth verification for implementations that encode CBOR differently.

  These structures now build on the new `OriginalBytesCborStructure`, which keeps the decoded bytes as `originalBytes` until the structure is modified. Setting or deleting a map entry drops them automatically; call `markModified()` after changing a nested value. `IssuerSignedItem.originalPayloadBytes` is deprecated in favour of `originalBytes`.

- 7f7b939: `DeviceEngagement.serverRetrievalMethods` is a single `ServerRetrievalMethod`, as ISO/IEC 18013-5 8.2.1.1 defines `ServerRetrievalMethods` as one map with optional `webApi` and `oidc` entries. Before, it was an array, so a device engagement with server retrieval methods could not be decoded. **Breaking:** pass a `ServerRetrievalMethod` instead of an array to `DeviceEngagement.create`.

  `DeviceEngagement.create` also no longer throws for every device engagement.

- 7f7b939: Handle versions as ISO/IEC 18013-5 8.1 defines them, where an unknown minor version must not cause an error:

  - A mobile security object with any `1.x` version is accepted. Before, only `1.0` was.
  - `DeviceResponse.verify` reports a FAILED `Device Response must have a supported version` check for a version other than `1.x`, instead of only checking that there is a version.
  - `Holder.verifyDeviceRequest` and `IsoMdocDcApi.parseRequest` report a FAILED `Device Request must have a supported version` check for a version other than `1.x`.

### Patch Changes

- 7f7b939: A `DeviceAuth` must contain either a `deviceSignature` or a `deviceMac` (ISO/IEC 18013-5 9.1.3.4), but decoding and `DeviceAuth.create` accepted one with both. `DeviceAuth.verify` then only verified the `deviceSignature` and ignored the `deviceMac`. Decoding and creating a `DeviceAuth` with both or neither now throws a `ValidationError`, and `DeviceAuth.verify` reports a FAILED `Device Auth must contain either a deviceSignature or deviceMac element, but not both` check for one.

  When verifying a device MAC threw an error, `DeviceAuth.verify` also reported a FAILED `Device Auth must contain a deviceSignature or deviceMac element` check. It now only reports the FAILED `Device MAC must be valid` check.

- 7f7b939: Fix device MAC authentication (ISO/IEC 18013-5 9.1.3.5), which could neither be created nor verified:

  - `DeviceResponse.verify` reported a FAILED `No Device Signature or Device Mac found on Device Auth` check after every device MAC, also a valid one, so `defaultVerificationCallback` threw for every response authenticated with a device MAC.
  - `DeviceResponse.createWithDeviceRequest` with `mac` threw a `CoseInvalidAlgorithmError`, and set the algorithm of the device key instead of HMAC 256/256 in the protected header. It now creates a device MAC with HMAC 256/256.
  - `DeviceSignedBuilder.tag` threw the same error, and derived the `EMacKey` with SHA-256 of the untagged session transcript instead of the `SessionTranscriptBytes`.
  - `DeviceSignedBuilder.tag` throws an `UnsupportedDeviceMacAlgorithmError` for any algorithm other than HMAC 256/256, since `DeviceAuth.verify` rejects any other device MAC.

  A session transcript passed as bytes may now be either the `SessionTranscript` or the `SessionTranscriptBytes` (tagged with tag 24) everywhere. Before, the device MAC key was only derived correctly from the tagged bytes. `SessionTranscript.from` normalizes either form.

- 833c17b: Forward the issuer's own `IssuerSignedItemBytes` when presenting a credential, instead of re-encoding each item from its decoded structure. A verifier digests the bytes it receives and compares them to `valueDigests`, so re-encoding made genuine claims from other CBOR encoders fail at the verifier.
- 337c841: Require the identifier list CWT's `typ` in the COSE protected header (RFC 9596 label 16) instead of as a CWT payload claim. Verification of an mdoc whose MSO carries an `identifierList` status previously failed with `Expected key '16' to be defined` against every issuer that follows the spec, since `typ` is a header parameter — the same place `@owf/token-status-list` writes it on a status list CWT. It is checked before the payload is decoded, so a token of another media type is rejected as such.

  Adds `IdentifierListCwtHeader`, a typed structure for the CWT's protected header (`alg`, `x5chain`, `typ`) alongside the existing `IdentifierListCwtPayload`.

- 833c17b: Verify `IssuerSignedItem` digests over the received tag-24 bytes instead of a re-encode, so credentials from other CBOR encoders still pass `isValid`.
- 7f7b939: A single certificate in an `x5chain` header is encoded as a byte string instead of an array with one byte string, as RFC 9360 and the examples of ISO/IEC 18013-5 Annex D encode it. This applies to the issuer auth of `Issuer.sign` and `IssuerSignedBuilder.sign`, and the reader auth of `IsoMdocDcApi.createRequest`. A chain of more than one certificate is still an array, and both forms are accepted when decoding.

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
