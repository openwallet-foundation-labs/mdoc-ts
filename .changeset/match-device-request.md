---
'@owf/mdoc': minor
---

Add `Verifier.matchDeviceRequest` and `Holder.matchDeviceRequest` to match a `DeviceRequest`. The verifier checks whether a `DeviceResponse` satisfies it, and the holder selects which credentials can answer which doc request. Both share the same matching and return the same nested result, so it shows what failed and not just that something failed:

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
          'org.iso.18013.5.1': { portrait: { optional: true } },
          // '*' applies to every element in the namespace
          'com.example.device': { '*': { source: 'deviceSigned' } },
        },
      },
    ],
  },
})
```

`DeviceResponse.verify`, `Verifier.verifyDeviceResponse` and `IsoMdocDcApi.verifyResponse` run the same match when you pass a `deviceRequest`, with the options in `deviceRequestMatchOptions` and the result in `deviceRequestMatch`. A failed match lists every missing element instead of stopping at the first one, and throws a `VerificationError` (which still extends `MdlError`) with the match attached as `error.assessment.result.match`. Match options that do not fit the device request throw an `InvalidDeviceRequestMatchOptionsError` before anything is verified. Elements a document disclosed that no doc request of its docType asked for are reported once per document as a `WARNING`.
