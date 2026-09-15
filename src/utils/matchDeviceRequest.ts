import type { VerificationCallback } from '../mdoc/check-callback'
import { InvalidDeviceRequestMatchOptionsError } from '../mdoc/errors'
import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'
import type { DeviceNamespaces } from '../mdoc/models/device-namespaces'
import type { DeviceRequest } from '../mdoc/models/device-request'
import type { DeviceResponse } from '../mdoc/models/device-response'
import type { DocType } from '../mdoc/models/doctype'
import type { IntentToRetain } from '../mdoc/models/intent-to-retain'
import { IssuerSigned } from '../mdoc/models/issuer-signed'
import type { IssuerSignedItem } from '../mdoc/models/issuer-signed-item'
import type { KeyAuthorizations } from '../mdoc/models/key-authorizations'
import type { Namespace } from '../mdoc/models/namespace'
import { describeAgeOverLimitViolations, findAgeOverCandidate, findAgeOverRequestLimitViolations } from './ageOver'
import { getOwnProperty } from './getOwnProperty'
import { isDeviceSignedElementAuthorized } from './keyAuthorizations'

export type DisclosedElementSource = 'issuerSigned' | 'deviceSigned'

export type DisclosedElement = {
  namespace: Namespace
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
}

/**
 * How a single requested element is matched. An `ItemsRequest` can express neither that an element
 * is optional nor where it is expected to come from, so the verifier — which built the request —
 * provides it as context to the match.
 */
export type ElementMatchOptions = {
  /**
   * Whether the response may leave this element out without failing the match. An optional element
   * never makes a document fail, but it is still reported per claim. Defaults to `false`.
   */
  optional?: boolean

  /**
   * Where the element may be disclosed from. Device-signed elements are asserted by the mdoc
   * itself and not by the issuer, so an element the issuer is expected to attest to, an
   * `age_over_NN` for instance, must not be answered from `deviceSigned`. Defaults to
   * `'issuerSigned'`.
   *
   * Even if `'deviceSigned'` is allowed, the element must be in the key authorizations of the mdoc.
   */
  source?: DisclosedElementSource | 'any'
}

export type DocRequestMatchOptions = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request these options apply to.
   */
  docRequestIndex: number

  /**
   * Per-element match options, keyed by namespace and element identifier. The element identifier
   * `'*'` applies to every element in the namespace that is not named explicitly, which is how a
   * namespace that is entirely device-signed is described.
   *
   * ```ts
   * {
   *   'org.iso.18013.5.1': { portrait: { optional: true } },
   *   'com.example.device': { '*': { source: 'deviceSigned' } },
   * }
   * ```
   */
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
}

/**
 * Per doc request the elements that are optional or that may be answered from `deviceSigned`. By
 * default every requested element is required and must be issuer-signed.
 */
export type DeviceRequestMatchOptions = {
  /**
   * A doc request can have options at most once.
   */
  docRequests?: Array<DocRequestMatchOptions>

  /**
   * A device request with more than one doc request does not say whether it asks for all of them, or
   * for any one of them. By default every doc request has to be satisfied. Set this to treat them as
   * alternatives instead, of which at least one has to be satisfied, which is a common
   * interpretation. The second edition of 18013-5 resolves the ambiguity with use cases in
   * `DeviceRequestInfo`, which are not supported yet.
   *
   * Does not apply to a device request with a single doc request. Defaults to `false`.
   */
  treatAmbiguousMultipleDocRequestsAsAlternatives?: boolean
}

export type ClaimMatchBase = {
  namespace: Namespace
  /**
   * The element identifier as it appears in the `ItemsRequest`.
   */
  elementIdentifier: DataElementIdentifier
  intentToRetain: IntentToRetain
  /**
   * Whether the element was matched as optional, and therefore cannot make the claims fail. Always
   * `false` when matching the credentials of a holder, as the request does not say which elements
   * are optional.
   */
  optional: boolean
}

export type ClaimMatchSuccess = ClaimMatchBase & {
  success: true
  /**
   * The element identifier that is disclosed. Only differs from `elementIdentifier` when an
   * `age_over_NN` request is answered with a different age attestation (18013-5 7.2.5).
   */
  disclosedElementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
}

export type ClaimMatchFailure = ClaimMatchBase & {
  success: false
  /**
   * `'notDisclosed'` — the document did not disclose the element, or the credential cannot: the
   * issuer did not sign it, and either the device key is not authorized for it or no value was
   * provided for it in the device namespaces.
   *
   * `'disallowedSource'` — the document did disclose it, but only from a source the match options
   * do not allow for this element. By default only `issuerSigned` is allowed, so a `deviceSigned`
   * element the verifier did not mark as device-signed fails here rather than counting as a match.
   *
   * `'deviceKeyNotAuthorized'` — the document did disclose it device-signed, from a source the match
   * options allow, but the device key is not authorized for it in the key authorizations of the MSO
   * (18013-5 9.1.3.4).
   */
  failure: 'notDisclosed' | 'disallowedSource' | 'deviceKeyNotAuthorized'
  /**
   * The source the element was disclosed from, when `failure` is `'disallowedSource'` or
   * `'deviceKeyNotAuthorized'`.
   */
  disclosedFrom?: DisclosedElementSource
  reason: string
}

export type ClaimMatch = ClaimMatchSuccess | ClaimMatchFailure

type NonEmptyArray<T> = [T, ...Array<T>]

export type DocTypeMatchSuccess = {
  success: true
  docType: DocType
}

export type DocTypeMatchFailure = {
  success: false
  /**
   * The docType of the document or credential.
   */
  docType: DocType
  reason: string
}

/**
 * Whether a document or credential has the docType the doc request asks for.
 */
export type DocTypeMatchResult = DocTypeMatchSuccess | DocTypeMatchFailure

/**
 * Every requested element that is not optional is disclosed.
 */
export type ClaimsMatchSuccess = {
  success: true
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The optional requested elements that are not disclosed, in request order.
   */
  failedClaims: Array<ClaimMatchFailure & { optional: true }>
}

/**
 * At least one requested element that is not optional is not disclosed.
 */
export type ClaimsMatchFailure = {
  success: false
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The requested elements that are not disclosed, in request order. Can contain optional elements.
   */
  failedClaims: NonEmptyArray<ClaimMatchFailure>
}

export type ClaimsMatchResult = ClaimsMatchSuccess | ClaimsMatchFailure

type UnrequestedClaims = {
  /**
   * Elements the document disclosed that the doc request did not ask for. Not a failure by itself
   * — it is the mdoc over-disclosing — but a verifier should not process data it did not request.
   */
  unrequestedClaims: Array<DisclosedElement>
}

export type DocumentClaimsMatchSuccess = ClaimsMatchSuccess & UnrequestedClaims
export type DocumentClaimsMatchFailure = ClaimsMatchFailure & UnrequestedClaims
export type DocumentClaimsMatchResult = DocumentClaimsMatchSuccess | DocumentClaimsMatchFailure

type DocumentMatchBase = {
  /**
   * Index into `deviceResponse.documents` of the document this result is about.
   */
  documentIndex: number
}

export type DocumentMatchSuccess = DocumentMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  claims: DocumentClaimsMatchSuccess
}

export type DocumentMatchFailure = DocumentMatchBase & {
  success: false
  docType: DocTypeMatchResult
  claims: DocumentClaimsMatchResult
}

/**
 * Whether a document satisfies a doc request. The `docType` check requires both the docType of the
 * document and the docType of its mobile security object to be the requested docType: the docType
 * outside the MSO is not signed.
 */
export type DocumentMatch = DocumentMatchSuccess | DocumentMatchFailure

type DocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The documents that do not satisfy this doc request, in response order. This includes every
   * document of another docType, for which the `docType` check failed.
   */
  failedDocuments: Array<DocumentMatchFailure>
}

export type DocRequestMatchSuccess = DocRequestMatchBase & {
  success: true
  /**
   * The documents that satisfy this doc request, in response order.
   */
  validDocuments: NonEmptyArray<DocumentMatchSuccess>
}

export type DocRequestMatchFailure = DocRequestMatchBase & {
  success: false
  validDocuments: []
}

export type DocRequestMatch = DocRequestMatchSuccess | DocRequestMatchFailure

type DocRequestsAsAlternatives = {
  /**
   * Whether the doc requests were matched as alternatives, of which at least one has to be
   * satisfied, rather than all of them. Only `true` when
   * `treatAmbiguousMultipleDocRequestsAsAlternatives` is set and the device request has more than
   * one doc request.
   */
  docRequestsAsAlternatives: boolean
}

type DeviceRequestMatchBase = DocRequestsAsAlternatives & {
  /**
   * Documents in the response whose docType no doc request asked for.
   */
  unrequestedDocuments: Array<{ documentIndex: number; docType: DocType }>
}

/**
 * Every doc request is satisfied or, when matched as alternatives, at least one of them.
 */
export type DeviceRequestMatchSuccess = DeviceRequestMatchBase &
  (
    | {
        success: true
        docRequestsAsAlternatives: false
        /**
         * One entry per doc request, in request order.
         */
        docRequests: Array<DocRequestMatchSuccess>
      }
    | {
        success: true
        docRequestsAsAlternatives: true
        /**
         * One entry per doc request, in request order. At least one is successful.
         */
        docRequests: Array<DocRequestMatch>
      }
  )

export type DeviceRequestMatchFailure = DeviceRequestMatchBase & {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<DocRequestMatch>
}

export type DeviceRequestMatchResult = DeviceRequestMatchSuccess | DeviceRequestMatchFailure

type CredentialMatchBase = {
  /**
   * Index into `credentials` of the credential this result is about.
   */
  credentialIndex: number
}

export type CredentialMatchSuccess = CredentialMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  claims: ClaimsMatchSuccess
}

export type CredentialMatchFailure = CredentialMatchBase & {
  success: false
  docType: DocTypeMatchResult
  claims: ClaimsMatchResult
}

/**
 * Whether a credential can satisfy a doc request. The `docType` check requires the docType of the
 * mobile security object of the credential to be the requested docType.
 */
export type CredentialMatch = CredentialMatchSuccess | CredentialMatchFailure

type HolderDocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The credentials that do not satisfy this doc request, in the order they were provided. This
   * includes every credential of another docType, for which the `docType` check failed. Empty when
   * the doc request is invalid, as credentials are then not matched.
   */
  failedCredentials: Array<CredentialMatchFailure>
}

export type HolderDocRequestMatchSuccess = HolderDocRequestMatchBase & {
  success: true
  /**
   * The credentials that satisfy this doc request, in the order they were provided.
   */
  validCredentials: NonEmptyArray<CredentialMatchSuccess>
}

/**
 * Why a doc request cannot be answered by any credential.
 *
 * `'ageOverLimitExceeded'` — the doc request asks for more than two `age_over_NN` elements in a
 * namespace, which 18013-5 7.2.5 forbids a reader to do, as together they narrow down the age of
 * the holder.
 */
export type InvalidDocRequest = {
  failure: 'ageOverLimitExceeded'
  reason: string
}

export type HolderDocRequestMatchFailure = HolderDocRequestMatchBase & {
  success: false
  validCredentials: []
  /**
   * Set when the doc request itself is invalid. No credential is then matched against it, so
   * `failedCredentials` is empty.
   */
  invalidDocRequest?: InvalidDocRequest
}

export type HolderDocRequestMatch = HolderDocRequestMatchSuccess | HolderDocRequestMatchFailure

/**
 * Every doc request can be answered or, when matched as alternatives, at least one of them.
 */
export type HolderDeviceRequestMatchSuccess =
  | {
      success: true
      docRequestsAsAlternatives: false
      /**
       * One entry per doc request, in request order.
       */
      docRequests: Array<HolderDocRequestMatchSuccess>
    }
  | {
      success: true
      docRequestsAsAlternatives: true
      /**
       * One entry per doc request, in request order. At least one is successful.
       */
      docRequests: Array<HolderDocRequestMatch>
    }

export type HolderDeviceRequestMatchFailure = DocRequestsAsAlternatives & {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<HolderDocRequestMatch>
}

export type HolderDeviceRequestMatchResult = HolderDeviceRequestMatchSuccess | HolderDeviceRequestMatchFailure

/**
 * A credential of the holder, with the values the holder can disclose device-signed for it.
 */
export type HolderCredential = {
  issuerSigned: IssuerSigned
  /**
   * The values the holder can disclose device-signed with this credential. A requested element the
   * issuer did not sign only matches when its value is here and the device key is authorized for
   * it, the same as when creating the response.
   */
  deviceNamespaces?: DeviceNamespaces
}

/**
 * Match a `DeviceResponse` against the `DeviceRequest` it answers (verifier side).
 *
 * The ISO mdoc DC API protocol (`org-iso-mdoc`) has no query language such as DCQL that describes
 * which claims a response has to contain, so this walks the device request itself and reports, per
 * doc request, per document and per check whether the response satisfies it.
 *
 * An element only counts as disclosed when it comes from `issuerSigned`, as `deviceSigned` elements
 * are asserted by the mdoc itself rather than by the issuer. Pass `matchOptions` to mark elements
 * that are optional or that are expected to be device-signed.
 *
 * By default the match only succeeds when every doc request is satisfied. Set
 * `treatAmbiguousMultipleDocRequestsAsAlternatives` in `matchOptions` to have it succeed when at
 * least one is.
 *
 * Shares its matching with {@link matchCredentialsToDeviceRequest}, which matches like a verifier
 * that accepts every element from `'any'` source.
 *
 * This is purely a structural comparison — it does not verify issuer auth, device auth or the
 * digests of the disclosed elements. Use it alongside `DeviceResponse.verify`, which runs it as
 * part of verification when a `deviceRequest` is passed.
 */
export const matchDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  deviceResponse: DeviceResponse
  matchOptions?: DeviceRequestMatchOptions
}): DeviceRequestMatchResult => {
  const { deviceRequest, deviceResponse, matchOptions } = options
  const docRequestOptions = indexDocRequestOptions(deviceRequest, matchOptions)

  // Every access to the mobile security object decodes it, so decode it once per document.
  const documents = (deviceResponse.documents ?? []).map((document) => ({
    document,
    mobileSecurityObject: document.issuerSigned.issuerAuth.mobileSecurityObject,
  }))

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): DocRequestMatch => {
    const { docType, namespaces } = docRequest.itemsRequest
    const elements = docRequestOptions.get(docRequestIndex)?.elements

    const documentMatches = documents.map(({ document, mobileSecurityObject }, documentIndex): DocumentMatch => {
      const mobileSecurityObjectDocType = mobileSecurityObject.docType
      const docTypeResult: DocTypeMatchResult =
        document.docType !== docType
          ? {
              success: false,
              docType: document.docType,
              reason: `Document has docType '${document.docType}', but docType '${docType}' was requested`,
            }
          : mobileSecurityObjectDocType !== docType
            ? {
                success: false,
                docType: document.docType,
                reason: `Document has docType '${docType}', but the mobile security object has docType '${mobileSecurityObjectDocType}'`,
              }
            : { success: true, docType }

      const { claims, unusedElements } = matchElements({
        mode: 'verifier',
        namespaces,
        elements,
        issuerSigned: document.issuerSigned,
        keyAuthorizations: mobileSecurityObject.deviceKeyInfo.keyAuthorizations,
        deviceNamespaces: document.deviceSigned.deviceNamespaces,
      })
      const claimsResult: DocumentClaimsMatchResult = {
        ...toClaimsMatchResult(claims),
        unrequestedClaims: unusedElements,
      }

      return docTypeResult.success && claimsResult.success
        ? { documentIndex, success: true, docType: docTypeResult, claims: claimsResult }
        : { documentIndex, success: false, docType: docTypeResult, claims: claimsResult }
    })

    const validDocuments = documentMatches.filter((documentMatch) => documentMatch.success)
    const failedDocuments = documentMatches.filter((documentMatch) => !documentMatch.success)

    return isNonEmptyArray(validDocuments)
      ? { docRequestIndex, docType, success: true, validDocuments, failedDocuments }
      : { docRequestIndex, docType, success: false, validDocuments: [], failedDocuments }
  })

  const requestedDocTypes = new Set(deviceRequest.docRequests.map((docRequest) => docRequest.itemsRequest.docType))
  const unrequestedDocuments = documents.flatMap(({ document }, documentIndex) =>
    requestedDocTypes.has(document.docType) ? [] : [{ documentIndex, docType: document.docType }]
  )

  if (matchDocRequestsAsAlternatives(deviceRequest, matchOptions?.treatAmbiguousMultipleDocRequestsAsAlternatives)) {
    return docRequests.some((docRequest) => docRequest.success)
      ? { success: true, docRequestsAsAlternatives: true, docRequests, unrequestedDocuments }
      : { success: false, docRequestsAsAlternatives: true, docRequests, unrequestedDocuments }
  }

  return docRequests.every((docRequest) => docRequest.success)
    ? { success: true, docRequestsAsAlternatives: false, docRequests, unrequestedDocuments }
    : { success: false, docRequestsAsAlternatives: false, docRequests, unrequestedDocuments }
}

/**
 * Match the credentials of a holder against a `DeviceRequest` (holder side), to select which
 * credentials can answer which doc request.
 *
 * Reports per doc request, per credential and per check whether the credential satisfies the doc
 * request, so a holder can show which credentials match, and for a credential of the right docType
 * which requested elements it is missing. Every credential is matched against every doc request, and
 * is referred to by its index in `credentials`.
 *
 * A requested element is disclosed issuer-signed when the issuer signed it (or, for an
 * `age_over_NN` request, the age attestation 18013-5 7.2.5 allows in its place). Otherwise it is
 * disclosed device-signed when the credential comes with a value for exactly that element in its
 * `deviceNamespaces`, and the device key is authorized for it in the key authorizations of the MSO.
 *
 * `DeviceResponse.createWithDeviceRequest` selects the elements to disclose the same way, so a
 * credential that matches can answer the doc request with the same `deviceNamespaces`. The request
 * does not say which elements are optional, so every requested element is required.
 *
 * A doc request that asks for more than two `age_over_NN` elements in a namespace (18013-5 7.2.5)
 * is not matched against any credential, and fails with `invalidDocRequest`.
 *
 * By default the match only succeeds when every doc request can be answered. Pass
 * `treatAmbiguousMultipleDocRequestsAsAlternatives` to have it succeed when at least one can.
 *
 * Shares its matching with {@link matchDeviceRequest}: a credential matches like a verifier that
 * accepts every element from `'any'` source would match the response. A verifier only accepts
 * issuer-signed elements by default, so a device-signed element only satisfies it when its match
 * options allow `deviceSigned` for it.
 */
export const matchCredentialsToDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  credentials: Array<IssuerSigned | HolderCredential>
  /**
   * See `DeviceRequestMatchOptions.treatAmbiguousMultipleDocRequestsAsAlternatives`. Defaults to
   * `false`.
   */
  treatAmbiguousMultipleDocRequestsAsAlternatives?: boolean
}): HolderDeviceRequestMatchResult => {
  const { deviceRequest } = options
  const credentials = options.credentials.map((credential) => {
    const { issuerSigned, deviceNamespaces }: HolderCredential =
      credential instanceof IssuerSigned ? { issuerSigned: credential } : credential

    // Every access to the mobile security object decodes it, so decode it once per credential.
    return { issuerSigned, deviceNamespaces, mobileSecurityObject: issuerSigned.issuerAuth.mobileSecurityObject }
  })

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): HolderDocRequestMatch => {
    const { docType, namespaces } = docRequest.itemsRequest

    const ageOverLimitViolations = findAgeOverRequestLimitViolations(namespaces)
    if (ageOverLimitViolations.length > 0) {
      return {
        docRequestIndex,
        docType,
        success: false,
        validCredentials: [],
        failedCredentials: [],
        invalidDocRequest: {
          failure: 'ageOverLimitExceeded',
          reason: `Doc request ${docRequestIndex} requests ${describeAgeOverLimitViolations(ageOverLimitViolations)}, but at most two age_over_NN elements may be requested per namespace`,
        },
      }
    }

    const credentialMatches = credentials.map(
      ({ issuerSigned, deviceNamespaces, mobileSecurityObject }, credentialIndex): CredentialMatch => {
        const credentialDocType = mobileSecurityObject.docType
        const docTypeResult: DocTypeMatchResult =
          credentialDocType === docType
            ? { success: true, docType }
            : {
                success: false,
                docType: credentialDocType,
                reason: `Credential has docType '${credentialDocType}', but docType '${docType}' was requested`,
              }

        const claimsResult = toClaimsMatchResult(
          matchElements({
            mode: 'holder',
            namespaces,
            issuerSigned,
            keyAuthorizations: mobileSecurityObject.deviceKeyInfo.keyAuthorizations,
            deviceNamespaces,
          }).claims
        )

        return docTypeResult.success && claimsResult.success
          ? { credentialIndex, success: true, docType: docTypeResult, claims: claimsResult }
          : { credentialIndex, success: false, docType: docTypeResult, claims: claimsResult }
      }
    )

    const validCredentials = credentialMatches.filter((credentialMatch) => credentialMatch.success)
    const failedCredentials = credentialMatches.filter((credentialMatch) => !credentialMatch.success)

    return isNonEmptyArray(validCredentials)
      ? { docRequestIndex, docType, success: true, validCredentials, failedCredentials }
      : { docRequestIndex, docType, success: false, validCredentials: [], failedCredentials }
  })

  if (matchDocRequestsAsAlternatives(deviceRequest, options.treatAmbiguousMultipleDocRequestsAsAlternatives)) {
    return docRequests.some((docRequest) => docRequest.success)
      ? { success: true, docRequestsAsAlternatives: true, docRequests }
      : { success: false, docRequestsAsAlternatives: true, docRequests }
  }

  return docRequests.every((docRequest) => docRequest.success)
    ? { success: true, docRequestsAsAlternatives: false, docRequests }
    : { success: false, docRequestsAsAlternatives: false, docRequests }
}

/**
 * Whether the doc requests are matched as alternatives. A single doc request is not ambiguous, so it
 * always has to be satisfied.
 */
const matchDocRequestsAsAlternatives = (
  deviceRequest: DeviceRequest,
  treatAmbiguousMultipleDocRequestsAsAlternatives = false
) => treatAmbiguousMultipleDocRequestsAsAlternatives && deviceRequest.docRequests.length > 1

type ElementCandidate = DisclosedElement & {
  /**
   * The issuer-signed item the element comes from, so a holder can disclose it as is.
   */
  issuerSignedItem?: IssuerSignedItem
}

/**
 * @internal
 */
export type ElementMatch =
  | {
      claim: ClaimMatchSuccess
      element: ElementCandidate
    }
  | { claim: ClaimMatchFailure; element?: undefined }

/**
 * Match the requested elements of a single doc request against a single document or credential.
 * Shared by the verifier and the holder side.
 *
 * - `verifier` matches the elements a document disclosed, from the source the `elements` options
 *   allow (by default `issuerSigned`).
 * - `holder` matches the elements a credential can disclose: issuer-signed when the issuer signed
 *   it, and otherwise device-signed when `deviceNamespaces` has a value for exactly that element.
 *   Device-signed values are provided by the holder itself, so an `age_over_NN` request is not
 *   answered with a device-signed value for another age.
 *
 * Either way a device-signed element only answers a request when the device key is authorized for
 * it (18013-5 9.1.3.4).
 *
 * @internal
 */
export const matchElements = (options: {
  mode: 'holder' | 'verifier'
  namespaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
  issuerSigned: IssuerSigned
  /**
   * The key authorizations in the mobile security object of `issuerSigned`, passed in so that the
   * caller decodes the mobile security object only once.
   */
  keyAuthorizations: KeyAuthorizations | undefined
  deviceNamespaces?: DeviceNamespaces
}): { claims: Array<ElementMatch>; unusedElements: Array<DisclosedElement> } => {
  const { mode, namespaces, keyAuthorizations } = options

  const available = collectElements(options.issuerSigned, options.deviceNamespaces)

  const claims: Array<ElementMatch> = []
  const usedElements = new Set<DisclosedElement>()

  const success = (claim: ClaimMatchBase, element: ElementCandidate) => {
    usedElements.add(element)
    claims.push({
      element,
      claim: {
        ...claim,
        success: true,
        disclosedElementIdentifier: element.elementIdentifier,
        elementValue: element.elementValue,
        source: element.source,
      },
    })
  }

  const failure = (
    claim: ClaimMatchBase,
    failure: Pick<ClaimMatchFailure, 'failure' | 'disclosedFrom' | 'reason'>,
    // The elements the document disclosed for the claim, so they are not also reported as unrequested.
    ...disclosed: Array<ElementCandidate | undefined>
  ) => {
    for (const element of disclosed) if (element) usedElements.add(element)
    claims.push({ claim: { ...claim, success: false, ...failure } })
  }

  for (const [namespace, requestedElements] of namespaces) {
    const issuerSignedInNamespace = available.filter(
      (element) => element.namespace === namespace && element.source === 'issuerSigned'
    )
    const deviceSignedInNamespace = available.filter(
      (element) => element.namespace === namespace && element.source === 'deviceSigned'
    )
    // 18013-5 9.1.3.4: device-signed elements only answer a request when the device key is
    // authorized for them.
    const authorizedDeviceSignedInNamespace = deviceSignedInNamespace.filter((element) =>
      isDeviceSignedElementAuthorized(keyAuthorizations, element)
    )
    const namespaceOptions = getOwnProperty(options.elements, namespace)

    for (const [elementIdentifier, intentToRetain] of requestedElements) {
      if (mode === 'holder') {
        const claim = { namespace, elementIdentifier, intentToRetain, optional: false }

        const element =
          findElement(elementIdentifier, issuerSignedInNamespace) ??
          authorizedDeviceSignedInNamespace.find((candidate) => candidate.elementIdentifier === elementIdentifier)
        if (element) {
          success(claim, element)
          continue
        }

        failure(claim, {
          failure: 'notDisclosed',
          reason: isDeviceSignedElementAuthorized(keyAuthorizations, { namespace, elementIdentifier })
            ? `Element '${elementIdentifier}' in namespace '${namespace}' is not issuer-signed in the credential, so it has to be disclosed device-signed, but no value was provided for it in the device namespaces`
            : `Element '${elementIdentifier}' in namespace '${namespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
        })
        continue
      }

      const { optional = false, source = 'issuerSigned' } =
        getOwnProperty(namespaceOptions, elementIdentifier) ?? getOwnProperty(namespaceOptions, '*') ?? {}
      const claim = { namespace, elementIdentifier, intentToRetain, optional }

      // The source is applied before the element is picked, so that an `age_over_NN` request is not
      // answered by a device-signed attestation while an issuer-signed one is also present.
      const element =
        source === 'deviceSigned'
          ? findElement(elementIdentifier, authorizedDeviceSignedInNamespace)
          : (findElement(elementIdentifier, issuerSignedInNamespace) ??
            (source === 'any' ? findElement(elementIdentifier, authorizedDeviceSignedInNamespace) : undefined))

      if (element) {
        success(claim, element)
        continue
      }

      // The element may still be there, just not in a way this verifier accepts for it — report
      // that rather than letting it pass or reporting it as absent. Both are marked as used, as the
      // doc request did ask for the element.
      //
      // Disclosed from a source that is not allowed:
      const disallowed =
        source === 'any'
          ? undefined
          : findElement(
              elementIdentifier,
              source === 'issuerSigned' ? deviceSignedInNamespace : issuerSignedInNamespace
            )
      // Disclosed device-signed from an allowed source, but every authorized element was already
      // tried above:
      const unauthorized =
        source === 'issuerSigned' ? undefined : findElement(elementIdentifier, deviceSignedInNamespace)

      // The unauthorized element is the one disclosed from the allowed source, so it is the failure
      // to report when both are there.
      if (unauthorized) {
        failure(
          claim,
          {
            failure: 'deviceKeyNotAuthorized',
            disclosedFrom: 'deviceSigned',
            reason: `Element '${unauthorized.elementIdentifier}' in namespace '${namespace}' was disclosed through deviceSigned, but the device key is not authorized for it in the mobile security object`,
          },
          unauthorized,
          disallowed
        )
        continue
      }

      if (disallowed) {
        failure(
          claim,
          {
            failure: 'disallowedSource',
            disclosedFrom: disallowed.source,
            reason: `Element '${disallowed.elementIdentifier}' in namespace '${namespace}' was disclosed through ${disallowed.source}, but must be disclosed through ${source}`,
          },
          disallowed
        )
        continue
      }

      failure(claim, {
        failure: 'notDisclosed',
        reason: `Element '${elementIdentifier}' in namespace '${namespace}' was not disclosed`,
      })
    }
  }

  return {
    claims,
    unusedElements: available
      .filter((element) => !usedElements.has(element))
      .map(({ issuerSignedItem: _, ...element }) => element),
  }
}

const toClaimsMatchResult = (claims: Array<ElementMatch>): ClaimsMatchResult => {
  const validClaims = claims.flatMap(({ claim }) => (claim.success ? [claim] : []))
  const failedClaims = claims.flatMap(({ claim }) => (claim.success ? [] : [claim]))

  if (isNonEmptyArray(failedClaims) && failedClaims.some((claim) => !claim.optional)) {
    return { success: false, validClaims, failedClaims }
  }

  // Every failed claim is optional, and optional elements never make the claims fail.
  return { success: true, validClaims, failedClaims: failedClaims.filter(isOptionalClaim) }
}

const isOptionalClaim = (claim: ClaimMatchFailure): claim is ClaimMatchFailure & { optional: true } => claim.optional

/**
 * The match options per doc request index, after checking that every option refers to a doc request
 * of the device request, and that no doc request has options more than once.
 */
const indexDocRequestOptions = (deviceRequest: DeviceRequest, matchOptions?: DeviceRequestMatchOptions) => {
  const docRequestOptions = new Map<number, DocRequestMatchOptions>()

  for (const options of matchOptions?.docRequests ?? []) {
    const { docRequestIndex } = options
    if (
      !Number.isInteger(docRequestIndex) ||
      docRequestIndex < 0 ||
      docRequestIndex >= deviceRequest.docRequests.length
    ) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options refer to doc request ${docRequestIndex}, but the device request has ${deviceRequest.docRequests.length} doc request(s)`
      )
    }
    if (docRequestOptions.has(docRequestIndex)) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options are provided more than once for doc request ${docRequestIndex}`
      )
    }
    docRequestOptions.set(docRequestIndex, options)
  }

  return docRequestOptions
}

/**
 * Throw an `InvalidDeviceRequestMatchOptionsError` when the match options do not fit the device
 * request, so that verification can fail on them before it does any work.
 *
 * @internal
 */
export const validateDeviceRequestMatchOptions = (
  deviceRequest: DeviceRequest,
  matchOptions?: DeviceRequestMatchOptions
) => {
  indexDocRequestOptions(deviceRequest, matchOptions)
}

const isNonEmptyArray = <T>(array: Array<T>): array is NonEmptyArray<T> => array.length > 0

/**
 * The element that answers a request for `elementIdentifier`, either by identifier or, for an age
 * attestation, by the substitution 18013-5 7.2.5 allows.
 *
 * @internal
 */
export const findElement = <Candidate extends { elementIdentifier: DataElementIdentifier; elementValue: unknown }>(
  elementIdentifier: DataElementIdentifier,
  candidates: Array<Candidate>
) =>
  candidates.find((candidate) => candidate.elementIdentifier === elementIdentifier) ??
  findAgeOverCandidate(elementIdentifier, candidates)

const collectElements = (issuerSigned: IssuerSigned, deviceNamespaces?: DeviceNamespaces) => {
  const elements: Array<ElementCandidate> = []

  for (const [namespace, issuerSignedItems] of issuerSigned.issuerNamespaces?.issuerNamespaces ?? []) {
    for (const issuerSignedItem of issuerSignedItems) {
      elements.push({
        namespace,
        elementIdentifier: issuerSignedItem.elementIdentifier,
        elementValue: issuerSignedItem.elementValue,
        source: 'issuerSigned',
        issuerSignedItem,
      })
    }
  }

  for (const [namespace, deviceSignedItems] of deviceNamespaces?.deviceNamespaces ?? []) {
    for (const [elementIdentifier, elementValue] of deviceSignedItems.deviceSignedItems) {
      elements.push({ namespace, elementIdentifier, elementValue, source: 'deviceSigned' })
    }
  }

  return elements
}

/**
 * Report a {@link DeviceRequestMatchResult} through a verification callback.
 *
 * A doc request that is not satisfied is a `FAILED` check; over-disclosure and documents that were
 * never requested are reported as `WARNING`, as they are the mdoc's doing and it is up to the
 * verifier whether to accept the response anyway. When the doc requests are matched as alternatives,
 * a single check is reported instead, which only fails when none of them is satisfied.
 *
 * The match is attached to the doc request checks as their structured `result`, so that it survives
 * a callback that throws on a `FAILED` check instead of collecting them.
 */
export const reportDeviceRequestMatch = (match: DeviceRequestMatchResult, onCheck: VerificationCallback) => {
  const result = { type: 'deviceRequestMatch', match } as const

  if (match.docRequestsAsAlternatives) {
    const check = `Device response must satisfy at least one of the alternative doc requests ${match.docRequests
      .map((docRequest) => `${docRequest.docRequestIndex} for docType '${docRequest.docType}'`)
      .join(', ')}`

    if (match.success) {
      onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
    } else {
      onCheck({
        status: 'FAILED',
        check,
        category: 'DOCUMENT_FORMAT',
        reason: match.docRequests
          .map((docRequest) => `Doc request ${docRequest.docRequestIndex}: ${docRequestFailureReason(docRequest)}`)
          .join('. '),
        result,
      })
    }
  } else {
    for (const docRequest of match.docRequests) {
      const check = `Device response must satisfy doc request ${docRequest.docRequestIndex} for docType '${docRequest.docType}'`

      if (docRequest.success) {
        onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
      } else {
        onCheck({
          status: 'FAILED',
          check,
          category: 'DOCUMENT_FORMAT',
          reason: docRequestFailureReason(docRequest),
          result,
        })
      }
    }
  }

  for (const { documentIndex, docRequestIndexes, unrequestedClaims } of findOverDisclosure(match)) {
    const docRequests =
      docRequestIndexes.length === 1
        ? `doc request ${docRequestIndexes[0]}`
        : `doc requests ${docRequestIndexes.join(', ')}`

    onCheck({
      status: 'WARNING',
      check: `Document ${documentIndex} must not disclose elements that were not requested`,
      category: 'DOCUMENT_FORMAT',
      reason: `Document ${documentIndex} disclosed ${unrequestedClaims
        .map((claim) => `'${claim.elementIdentifier}' in namespace '${claim.namespace}'`)
        .join(', ')}, which ${docRequests} did not ask for`,
    })
  }

  if (match.unrequestedDocuments.length > 0) {
    onCheck({
      status: 'WARNING',
      check: 'Device response must not contain documents that were not requested',
      category: 'DOCUMENT_FORMAT',
      reason: `Device response contains ${match.unrequestedDocuments
        .map((document) => `document ${document.documentIndex} with docType '${document.docType}'`)
        .join(', ')}, which the device request did not ask for`,
    })
  }
}

/**
 * Per document, the elements it disclosed that no doc request it may answer asked for, in response
 * order. The response does not say which doc request a document answers, so every doc request of
 * its docType is considered, also one the document fails: with two doc requests of the same
 * docType, an element is only over-disclosed when neither asks for it. A document of another docType
 * does not answer the doc request, and is reported as an unrequested document instead.
 */
const findOverDisclosure = (match: DeviceRequestMatchResult) => {
  const documents = new Map<number, { docRequestIndexes: Array<number>; unrequestedClaims: Array<DisclosedElement> }>()

  for (const docRequest of match.docRequests) {
    for (const document of [...docRequest.validDocuments, ...docRequest.failedDocuments]) {
      if (!document.docType.success) continue

      const { unrequestedClaims } = document.claims
      const overDisclosure = documents.get(document.documentIndex)
      if (!overDisclosure) {
        documents.set(document.documentIndex, { docRequestIndexes: [docRequest.docRequestIndex], unrequestedClaims })
        continue
      }

      overDisclosure.docRequestIndexes.push(docRequest.docRequestIndex)
      overDisclosure.unrequestedClaims = overDisclosure.unrequestedClaims.filter((claim) =>
        unrequestedClaims.some(
          (other) =>
            other.namespace === claim.namespace &&
            other.elementIdentifier === claim.elementIdentifier &&
            other.source === claim.source
        )
      )
    }
  }

  return Array.from(documents, ([documentIndex, overDisclosure]) => ({ documentIndex, ...overDisclosure }))
    .filter(({ unrequestedClaims }) => unrequestedClaims.length > 0)
    .sort((a, b) => a.documentIndex - b.documentIndex)
}

const docRequestFailureReason = (docRequest: DocRequestMatch) => {
  // Documents of another docType are not an attempt to answer this doc request.
  const documents = docRequest.failedDocuments.filter(
    (document) => document.docType.success || document.docType.docType === docRequest.docType
  )

  if (documents.length === 0) {
    return `Device response does not contain a document with docType '${docRequest.docType}'`
  }

  return documents
    .map((document) => {
      if (!document.docType.success) return `Document ${document.documentIndex}: ${document.docType.reason}`

      const failedClaims = document.claims.failedClaims.filter((claim) => !claim.optional)
      return `Document ${document.documentIndex}: ${failedClaims.map((claim) => claim.reason).join('; ')}`
    })
    .join('. ')
}
