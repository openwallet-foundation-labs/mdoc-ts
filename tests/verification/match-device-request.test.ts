import { assert, describe, expect, expectTypeOf, test } from 'vitest'
import { z } from 'zod'
import {
  CoseKey,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSigned,
  DeviceSignedItems,
  DocRequest,
  type DocTypeMatchSuccess,
  Document,
  type DocumentClaimsMatchSuccess,
  DocumentError,
  InvalidDeviceRequestMatchOptionsError,
  IssuerSigned,
  ItemsRequest,
  KeyAuthorizations,
  SessionTranscript,
  type VerificationAssessment,
  VerificationError,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, issuerCertificate, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const sessionTranscript = SessionTranscript.create({ handover: NullHandover.fromEncodedStructure(null) })

const createDeviceRequest = (
  docRequests: Array<{ docType?: string; namespaces: Record<string, Record<string, boolean>> }>
) =>
  DeviceRequest.create({
    docRequests: docRequests.map(({ docType, namespaces }) =>
      DocRequest.create({ itemsRequest: ItemsRequest.create({ docType: docType ?? mdlDocType, namespaces }) })
    ),
  })

/**
 * Build a response for `disclosedRequest` — the request the mdoc answered — so it can be matched
 * against a different request to model a partial or over-disclosing response.
 */
const createDeviceResponse = async (options: {
  deviceRequest: DeviceRequest
  issuerSigned: Array<IssuerSigned>
  deviceNamespaces?: DeviceNamespaces
}) =>
  await DeviceResponse.createWithDeviceRequest(
    {
      deviceRequest: options.deviceRequest,
      sessionTranscript,
      documents: options.issuerSigned.map((issuerSigned, docRequestIndex) => ({
        issuerSigned,
        docRequestIndex,
        deviceNamespaces: options.deviceNamespaces,
        signature: { signingKey: deviceKey },
      })),
    },
    mdocContext
  )

describe('matchDeviceRequest', () => {
  test('a response disclosing every requested element satisfies the request', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false } } },
    ])
    const deviceResponse = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.unrequestedDocuments).toHaveLength(0)
    expect(match.docRequests).toHaveLength(1)

    const [docRequest] = match.docRequests
    expect(docRequest).toMatchObject({ docRequestIndex: 0, docType: mdlDocType, success: true })
    expect(docRequest.validDocuments).toHaveLength(1)
    expect(docRequest.failedDocuments).toHaveLength(0)

    assert(docRequest.success)
    const [document] = docRequest.validDocuments
    expect(document).toMatchObject({
      documentIndex: 0,
      success: true,
      docType: { success: true, docType: mdlDocType },
      claims: { success: true, failedClaims: [], unrequestedClaims: [] },
    })
    expect(document.claims.validClaims).toStrictEqual([
      {
        success: true,
        namespace: mdlNamespace,
        elementIdentifier: 'family_name',
        intentToRetain: true,
        optional: false,
        disclosedElementIdentifier: 'family_name',
        elementValue: 'Doe',
        source: 'issuerSigned',
      },
      {
        success: true,
        namespace: mdlNamespace,
        elementIdentifier: 'given_name',
        intentToRetain: false,
        optional: false,
        disclosedElementIdentifier: 'given_name',
        elementValue: 'John',
        source: 'issuerSigned',
      },
    ])
  })

  test('an element the mdoc withheld is reported per claim, not as a missing document', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)

    // The document has the requested docType, but not every requested claim.
    const [document] = match.docRequests[0].failedDocuments
    expect(document).toMatchObject({ success: false, docType: { success: true }, claims: { success: false } })
    expect(document.claims.validClaims.map((claim) => claim.elementIdentifier)).toStrictEqual(['family_name'])
    expect(document.claims.failedClaims).toStrictEqual([
      {
        success: false,
        namespace: mdlNamespace,
        elementIdentifier: 'birth_date',
        intentToRetain: true,
        optional: false,
        failure: 'notDisclosed',
        reason: `Element 'birth_date' in namespace '${mdlNamespace}' was not disclosed`,
      },
    ])
  })

  test('elements the mdoc disclosed but the request did not ask for are reported as unrequested', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    // Over-disclosure does not make the request unsatisfied — it is reported separately.
    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validDocuments[0].claims.unrequestedClaims).toStrictEqual([
      { namespace: mdlNamespace, elementIdentifier: 'birth_date', elementValue: '1990-01-01', source: 'issuerSigned' },
    ])
  })

  test('a doc request answered by no document reports the docType and the document error code', async () => {
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: true } } },
    ])

    const disclosed = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const deviceResponse = DeviceResponse.createSimple({
      documents: disclosed.documents,
      documentErrors: [DocumentError.create({ documentError: new Map([[photoIdDocType, 0]]) })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].success).toBe(true)
    expect(match.docRequests[1]).toMatchObject({
      docRequestIndex: 1,
      docType: photoIdDocType,
      success: false,
      validDocuments: [],
    })
    // The mDL was matched against the photo ID doc request as well, and failed on its docType.
    expect(match.docRequests[1].failedDocuments[0].docType).toStrictEqual({
      success: false,
      docType: mdlDocType,
      reason: `Document has docType '${mdlDocType}', but docType '${photoIdDocType}' was requested`,
    })
  })

  test('an age_over_NN request is satisfied by a different age attestation (18013-5 7.2.5)', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_21: true } } }])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned({ claims: { age_over_21: true } })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    const [document] = docRequest.validDocuments
    expect(document.claims.validClaims[0]).toMatchObject({
      success: true,
      elementIdentifier: 'age_over_18',
      disclosedElementIdentifier: 'age_over_21',
      elementValue: true,
    })
    // The substituted attestation answers the request, so it is not over-disclosure.
    expect(document.claims.unrequestedClaims).toHaveLength(0)
  })

  /**
   * An MSO that authorizes the device key to self-assert an age attestation in the mDL namespace.
   * The mdoc cannot build such a response without it (9.1.3.4), and the verifier should still not
   * accept the result as an answer to a request for an issuer-signed attestation.
   */
  const ageOverKeyAuthorizations = KeyAuthorizations.create({
    dataElements: new Map([[mdlNamespace, ['age_over_21']]]),
  })

  test('a device-signed element only matches when the verifier marked it as device-signed', async () => {
    const deviceNamespace = 'com.example.device'
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    // A requested element the issuer did not sign can be answered from the device namespaces.
    const deviceResponse = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [
        await createIssuerSigned({
          keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
        }),
      ],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [deviceNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['session_id', 'abc']]) })],
        ]),
      }),
    })

    // Without the element options the device-signed element does not answer the request.
    const withoutOptions = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    expect(withoutOptions.success).toBe(false)
    expect(withoutOptions.docRequests[0].failedDocuments[0].claims.failedClaims[0]).toMatchObject({
      success: false,
      failure: 'disallowedSource',
      disclosedFrom: 'deviceSigned',
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [deviceNamespace]: { '*': { source: 'deviceSigned' } } } }],
      },
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    const claim = docRequest.validDocuments[0].claims.validClaims[1]
    expect(claim).toMatchObject({
      success: true,
      namespace: deviceNamespace,
      elementIdentifier: 'session_id',
      elementValue: 'abc',
      source: 'deviceSigned',
    })
  })

  test('a device-signed element the device key is not authorized for is reported once, on its claim', async () => {
    const deviceNamespace = 'com.example.device'
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    // `createWithDeviceRequest` refuses to authenticate unauthorized elements (18013-5 9.1.3.4), so
    // the MSO is swapped for one without key authorizations afterwards, as a non-conformant mdoc
    // would produce it.
    const authorized = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [
        await createIssuerSigned({ keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }) }),
      ],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [deviceNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['session_id', 'abc']]) })],
        ]),
      }),
    })
    const [document] = authorized.documents ?? []
    const deviceResponse = DeviceResponse.createSimple({
      documents: [
        Document.create({
          docType: document.docType,
          issuerSigned: IssuerSigned.create({
            issuerAuth: (await createIssuerSigned()).issuerAuth,
            issuerNamespaces: document.issuerSigned.issuerNamespaces,
          }),
          deviceSigned: document.deviceSigned,
        }),
      ],
    })

    // By default the element must be issuer-signed, so it is disclosed from a disallowed source.
    const withoutOptions = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })
    const [withoutOptionsDocument] = withoutOptions.docRequests[0].failedDocuments
    expect(withoutOptionsDocument.claims.failedClaims).toEqual([
      expect.objectContaining({
        elementIdentifier: 'session_id',
        failure: 'disallowedSource',
        disclosedFrom: 'deviceSigned',
      }),
    ])
    expect(withoutOptionsDocument.claims.unrequestedClaims).toStrictEqual([])

    // Allowed from deviceSigned, it still does not answer the request without the authorization.
    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [deviceNamespace]: { '*': { source: 'deviceSigned' } } } }],
      },
    })
    const [matchDocument] = match.docRequests[0].failedDocuments
    expect(matchDocument.claims.failedClaims).toStrictEqual([
      {
        success: false,
        namespace: deviceNamespace,
        elementIdentifier: 'session_id',
        intentToRetain: false,
        optional: false,
        failure: 'deviceKeyNotAuthorized',
        disclosedFrom: 'deviceSigned',
        reason: `Element 'session_id' in namespace '${deviceNamespace}' was disclosed through deviceSigned, but the device key is not authorized for it in the mobile security object`,
      },
    ])
    expect(matchDocument.claims.unrequestedClaims).toStrictEqual([])
  })

  test('an unauthorized device-signed element is reported when an issuer-signed one is also present', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const [document] =
      (await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })).documents ?? []

    // The mdoc also self-asserts family_name, which the MSO does not authorize the device key for.
    // Device auth is not part of the match, so it is kept as is.
    const deviceResponse = DeviceResponse.createSimple({
      documents: [
        Document.create({
          docType: document.docType,
          issuerSigned: document.issuerSigned,
          deviceSigned: DeviceSigned.create({
            deviceNamespaces: DeviceNamespaces.create({
              deviceNamespaces: new Map([
                [mdlNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['family_name', 'Roe']]) })],
              ]),
            }),
            deviceAuth: document.deviceSigned.deviceAuth,
          }),
        }),
      ],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [
          { docRequestIndex: 0, elements: { [mdlNamespace]: { family_name: { source: 'deviceSigned' } } } },
        ],
      },
    })

    // The device-signed element is disclosed from the allowed source, so its missing authorization is
    // the failure, and neither disclosed family_name is unrequested.
    const [matchDocument] = match.docRequests[0].failedDocuments
    expect(matchDocument.claims.failedClaims).toEqual([
      expect.objectContaining({ failure: 'deviceKeyNotAuthorized', disclosedFrom: 'deviceSigned' }),
    ])
    expect(matchDocument.claims.unrequestedClaims).toStrictEqual([])
  })

  test('a device-signed age attestation does not answer a request for an issuer-signed one', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, age_over_21: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    // An mdoc that self-asserts age_over_21 in the namespace the issuer signs. The MSO authorizes
    // the device key for it, which 18013-5 9.1.3.4 allows but 7.2.1 does not — every Table 5
    // element "shall be returned as part of the IssuerSignedItems".
    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned({ keyAuthorizations: ageOverKeyAuthorizations })],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [mdlNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['age_over_21', true]]) })],
        ]),
      }),
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    const claim = match.docRequests[0].failedDocuments[0].claims.failedClaims[0]
    expect(claim).toMatchObject({
      success: false,
      elementIdentifier: 'age_over_18',
      failure: 'disallowedSource',
      disclosedFrom: 'deviceSigned',
    })
    expect(claim.reason).toContain('must be disclosed through issuerSigned')
  })

  test('an issuer-signed element still answers the request when a device-signed one is also present', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { age_over_18: true, age_over_21: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [
        await createIssuerSigned({
          claims: { age_over_18: true },
          keyAuthorizations: ageOverKeyAuthorizations,
        }),
      ],
      deviceNamespaces: DeviceNamespaces.create({
        deviceNamespaces: new Map([
          [mdlNamespace, DeviceSignedItems.create({ deviceSignedItems: new Map([['age_over_21', true]]) })],
        ]),
      }),
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    const [document] = docRequest.validDocuments
    expect(document.claims.validClaims[0]).toMatchObject({
      success: true,
      disclosedElementIdentifier: 'age_over_18',
      source: 'issuerSigned',
    })
    // The self-asserted attestation was not requested from deviceSigned.
    expect(document.claims.unrequestedClaims).toStrictEqual([
      { namespace: mdlNamespace, elementIdentifier: 'age_over_21', elementValue: true, source: 'deviceSigned' },
    ])
  })

  test('an optional element the mdoc withheld does not fail the match', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: false } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [mdlNamespace]: { portrait: { optional: true } } } }],
      },
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    // The absence is still reported per claim, it just does not make the document fail.
    expect(docRequest.validDocuments[0].claims.failedClaims[0]).toMatchObject({
      success: false,
      elementIdentifier: 'portrait',
      optional: true,
      failure: 'notDisclosed',
    })
  })

  test('a successful match is typed as successful down to every check', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    assert(match.success && !match.docRequestsAsAlternatives)
    const [document] = match.docRequests[0].validDocuments
    expectTypeOf(document.docType).toEqualTypeOf<DocTypeMatchSuccess>()
    expectTypeOf(document.claims).toEqualTypeOf<DocumentClaimsMatchSuccess>()
    // Only optional elements can be missing from a successful claims check.
    expectTypeOf<(typeof document.claims.failedClaims)[number]['optional']>().toEqualTypeOf<true>()
    expect(document.docType.success && document.claims.success).toBe(true)
  })

  test('a document whose MSO docType differs from its docType does not answer the doc request', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { docType: 'org.iso.23220.photoid.1', namespaces: { [mdlNamespace]: { family_name: true } } },
    ])

    const disclosed = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })
    const [document] = disclosed.documents ?? []

    // The docType outside the MSO is not signed, so an mdoc can claim any docType for a document
    // the issuer attested to under a different one.
    const deviceResponse = DeviceResponse.createSimple({
      documents: [
        Document.create({
          docType: 'org.iso.23220.photoid.1',
          issuerSigned: document.issuerSigned,
          deviceSigned: document.deviceSigned,
        }),
      ],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].failedDocuments[0].docType).toMatchObject({ success: false })
    expect(match.docRequests[0].failedDocuments[0].docType).toHaveProperty(
      'reason',
      expect.stringContaining(mdlDocType)
    )
  })

  test('documents the device request did not ask for are reported', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { docType: 'org.iso.23220.photoid.1', namespaces: { [mdlNamespace]: { family_name: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned(), await createIssuerSigned({ docType: 'org.iso.23220.photoid.1' })],
    })

    const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

    expect(match.success).toBe(true)
    expect(match.unrequestedDocuments).toHaveLength(1)
    expect(match.unrequestedDocuments[0]).toMatchObject({ documentIndex: 1, docType: 'org.iso.23220.photoid.1' })
  })

  test('match options apply per doc request, also when two doc requests have the same docType', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 1, elements: { [mdlNamespace]: { portrait: { optional: true } } } }],
      },
    })

    expect(match.docRequests.map((docRequest) => docRequest.success)).toEqual([false, true])
    expect(match.success).toBe(false)
  })

  test.each([
    [1, 'Match options refer to doc request 1, but the device request has 1 doc request(s)'],
    [-1, 'Match options refer to doc request -1, but the device request has 1 doc request(s)'],
    [0.5, 'Match options refer to doc request 0.5, but the device request has 1 doc request(s)'],
  ])('match options for doc request %s, which the device request does not have, are rejected', async (docRequestIndex, message) => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })

    expect(() =>
      Verifier.matchDeviceRequest({
        deviceRequest,
        deviceResponse,
        matchOptions: { docRequests: [{ docRequestIndex, elements: {} }] },
      })
    ).toThrow(new InvalidDeviceRequestMatchOptionsError(message))
  })

  test('match options for the same doc request more than once are rejected', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })

    expect(() =>
      Verifier.matchDeviceRequest({
        deviceRequest,
        deviceResponse,
        matchOptions: { docRequests: [{ docRequestIndex: 0 }, { docRequestIndex: 0, elements: {} }] },
      })
    ).toThrow(new InvalidDeviceRequestMatchOptionsError('Match options are provided more than once for doc request 0'))
  })

  describe('treatAmbiguousMultipleDocRequestsAsAlternatives', () => {
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const alternativesRequest = () =>
      createDeviceRequest([
        { namespaces: { [mdlNamespace]: { family_name: true } } },
        { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: true } } },
      ])

    test('multiple doc requests all have to be satisfied by default', async () => {
      const deviceRequest = alternativesRequest()
      const deviceResponse = await createDeviceResponse({
        deviceRequest,
        issuerSigned: [await createIssuerSigned()],
      })

      const match = Verifier.matchDeviceRequest({ deviceRequest, deviceResponse })

      expect(match).toMatchObject({ success: false, docRequestsAsAlternatives: false })
      expect(match.docRequests.map((docRequest) => docRequest.success)).toEqual([true, false])
    })

    test('a response satisfying one of the alternatives satisfies the request', async () => {
      const deviceRequest = alternativesRequest()
      const deviceResponse = await createDeviceResponse({
        deviceRequest,
        issuerSigned: [await createIssuerSigned()],
      })

      const match = Verifier.matchDeviceRequest({
        deviceRequest,
        deviceResponse,
        matchOptions: { treatAmbiguousMultipleDocRequestsAsAlternatives: true },
      })

      expect(match).toMatchObject({ success: true, docRequestsAsAlternatives: true })
      expect(match.docRequests.map((docRequest) => docRequest.success)).toEqual([true, false])

      assert(match.success)
      // A successful match of alternatives does not narrow every doc request to successful.
      if (match.docRequestsAsAlternatives) {
        expectTypeOf<(typeof match.docRequests)[number]['success']>().toEqualTypeOf<boolean>()
      }
    })

    test('a response satisfying none of the alternatives does not satisfy the request', async () => {
      const disclosedRequest = createDeviceRequest([
        { docType: 'org.example.other', namespaces: { [mdlNamespace]: { family_name: true } } },
      ])
      const deviceResponse = await createDeviceResponse({
        deviceRequest: disclosedRequest,
        issuerSigned: [await createIssuerSigned({ docType: 'org.example.other' })],
      })

      const match = Verifier.matchDeviceRequest({
        deviceRequest: alternativesRequest(),
        deviceResponse,
        matchOptions: { treatAmbiguousMultipleDocRequestsAsAlternatives: true },
      })

      expect(match).toMatchObject({ success: false, docRequestsAsAlternatives: true })
    })

    test('a single doc request is not ambiguous, so it is not matched as an alternative', async () => {
      const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
      const deviceResponse = await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })

      const match = Verifier.matchDeviceRequest({
        deviceRequest,
        deviceResponse,
        matchOptions: { treatAmbiguousMultipleDocRequestsAsAlternatives: true },
      })

      expect(match).toMatchObject({ success: true, docRequestsAsAlternatives: false })
    })

    test('verify reports a single check for the alternatives', async () => {
      const deviceRequest = alternativesRequest()
      const deviceResponse = await createDeviceResponse({
        deviceRequest,
        issuerSigned: [await createIssuerSigned()],
      })

      const verify = async (disclosedResponse: DeviceResponse) => {
        const checks: Array<VerificationAssessment> = []
        await disclosedResponse.verify(
          {
            deviceRequest,
            deviceRequestMatchOptions: { treatAmbiguousMultipleDocRequestsAsAlternatives: true },
            sessionTranscript,
            trustedCertificates: [],
            disableCertificateChainValidation: true,
            onCheck: (check) => checks.push(check),
          },
          mdocContext
        )
        return checks.filter((check) => check.check.startsWith('Device response must satisfy'))
      }

      expect(await verify(deviceResponse)).toMatchObject([
        {
          status: 'PASSED',
          check: `Device response must satisfy at least one of the alternative doc requests 0 for docType '${mdlDocType}', 1 for docType '${photoIdDocType}'`,
        },
      ])

      expect(await verify(DeviceResponse.createSimple({ documents: [] }))).toMatchObject([
        {
          status: 'FAILED',
          reason: `Doc request 0: Device response does not contain a document with docType '${mdlDocType}'. Doc request 1: Device response does not contain a document with docType '${photoIdDocType}'`,
        },
      ])
    })
  })

  test('accepts encoded device requests and responses', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({
      deviceRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const match = Verifier.matchDeviceRequest({
      deviceRequest: deviceRequest.encode(),
      deviceResponse: deviceResponse.encode(),
    })

    expect(match.success).toBe(true)
  })
})

describe('DeviceResponse.verify with a device request', () => {
  const trustedCertificates: Array<{ issuance: Uint8Array[] }> = []

  test('an unsatisfied doc request is a FAILED check', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const checks: Array<VerificationAssessment> = []
    const { deviceRequestMatch } = await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    const check = checks.find((c) => c.check.startsWith('Device response must satisfy doc request 0'))
    expect(check?.status).toBe('FAILED')
    expect(check?.reason).toContain('birth_date')

    // A collecting callback does not throw, so the match is returned instead.
    expect(deviceRequestMatch?.success).toBe(false)
    expect(deviceRequestMatch?.docRequests[0].failedDocuments[0].claims.failedClaims[0]).toMatchObject({
      elementIdentifier: 'birth_date',
      failure: 'notDisclosed',
    })
  })

  test('over-disclosure is a WARNING, not a failure', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    const checks: Array<VerificationAssessment> = []
    await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(checks.find((c) => c.check.startsWith('Device response must satisfy doc request 0'))?.status).toBe('PASSED')

    const warning = checks.find((c) => c.check.includes('must not disclose elements that were not requested'))
    expect(warning?.status).toBe('WARNING')
    expect(warning?.reason).toContain('birth_date')
  })

  test('over-disclosure is a WARNING also for a document that misses a requested element', async () => {
    const photoIdDocType = 'org.iso.23220.photoid.1'
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
      { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: true } } },
    ])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned(), await createIssuerSigned({ docType: photoIdDocType })],
    })

    const checks: Array<VerificationAssessment> = []
    await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(checks.find((c) => c.check.startsWith('Device response must satisfy doc request 0'))?.status).toBe('FAILED')

    // The document of another docType does not answer the doc request, so it is reported as an
    // unrequested document rather than as over-disclosing for it.
    const warnings = checks.filter((c) => c.check.includes('must not disclose elements that were not requested'))
    expect(warnings).toStrictEqual([
      {
        status: 'WARNING',
        check: 'Document 0 must not disclose elements that were not requested',
        category: 'DOCUMENT_FORMAT',
        reason: `Document 0 disclosed 'birth_date' in namespace '${mdlNamespace}', which doc request 0 did not ask for`,
      },
    ])
    expect(
      checks.find((c) => c.check === 'Device response must not contain documents that were not requested')?.reason
    ).toContain(`document 1 with docType '${photoIdDocType}'`)
  })

  test('over-disclosure is judged against every doc request of the docType of a document', async () => {
    const disclosedRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: true } } },
      { namespaces: { [mdlNamespace]: { birth_date: true } } },
    ])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { namespaces: { [mdlNamespace]: { birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned(), await createIssuerSigned()],
    })

    const checks: Array<VerificationAssessment> = []
    const { deviceRequestMatch } = await deviceResponse.verify(
      {
        deviceRequest,
        sessionTranscript,
        trustedCertificates,
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )

    expect(deviceRequestMatch?.success).toBe(true)

    // Each document answers one of the doc requests, so what the other one asks for is not
    // over-disclosure. Only given_name, which neither asks for, is — reported once.
    const warnings = checks.filter((c) => c.check.includes('must not disclose elements that were not requested'))
    expect(warnings).toStrictEqual([
      {
        status: 'WARNING',
        check: 'Document 0 must not disclose elements that were not requested',
        category: 'DOCUMENT_FORMAT',
        reason: `Document 0 disclosed 'given_name' in namespace '${mdlNamespace}', which doc requests 0, 1 did not ask for`,
      },
    ])
  })

  test('invalid match options are rejected before the response is verified', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceResponse = await createDeviceResponse({ deviceRequest, issuerSigned: [await createIssuerSigned()] })

    const checks: Array<VerificationAssessment> = []
    await expect(
      deviceResponse.verify(
        {
          deviceRequest,
          deviceRequestMatchOptions: { docRequests: [{ docRequestIndex: 1 }] },
          sessionTranscript,
          trustedCertificates,
          disableCertificateChainValidation: true,
          onCheck: (check) => checks.push(check),
        },
        mdocContext
      )
    ).rejects.toThrow(InvalidDeviceRequestMatchOptionsError)
    expect(checks).toStrictEqual([])
  })

  test('the default verification callback throws a VerificationError carrying the match', async () => {
    const disclosedRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, birth_date: true } } },
    ])

    const deviceResponse = await createDeviceResponse({
      deviceRequest: disclosedRequest,
      issuerSigned: [await createIssuerSigned()],
    })

    // The other tests collect the checks, so this one has to actually pass issuer auth to reach
    // the doc request check that the default callback throws on.
    const error = await deviceResponse
      .verify(
        {
          deviceRequest,
          sessionTranscript,
          trustedCertificates: [{ issuance: [issuerCertificate] }],
        },
        mdocContext
      )
      .then(
        () => undefined,
        (error) => error
      )

    expect(error).toBeInstanceOf(VerificationError)
    const { assessment } = error as VerificationError
    expect(assessment.status).toBe('FAILED')
    expect(assessment.check).toContain('doc request 0')

    // The structured match survives the throw, so a caller that does not collect the checks itself
    // can still see which claim failed and why.
    expect(assessment.result?.type).toBe('deviceRequestMatch')
    const match = assessment.result?.match
    expect(match?.success).toBe(false)
    expect(match?.docRequests[0].failedDocuments[0].claims.failedClaims).toEqual([
      expect.objectContaining({ elementIdentifier: 'birth_date', failure: 'notDisclosed' }),
    ])
  })
})
