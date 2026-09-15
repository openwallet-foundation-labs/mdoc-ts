import { assert, describe, expect, test } from 'vitest'
import { z } from 'zod'
import {
  AgeOverLimitExceededError,
  CoseKey,
  DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  DeviceSignedItems,
  DocRequest,
  DocTypeMismatchError,
  Holder,
  InvalidElementSelectionError,
  ItemsRequest,
  KeyAuthorizations,
  MissingRequestedElementError,
  SessionTranscript,
  type VerificationAssessment,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import { DEVICE_JWK_PRIVATE } from '../config'
import { mdocContext } from '../context'
import { createIssuerSigned, mdlDocType, mdlNamespace } from '../iso-mdoc-dc-api/fixtures'

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

const deviceKey = CoseKey.fromJwk(DEVICE_JWK_PRIVATE)
const sessionTranscript = SessionTranscript.create({ handover: NullHandover.fromEncodedStructure(null) })

const photoIdDocType = 'org.iso.23220.photoid.1'
const deviceNamespace = 'com.example.device'

const createDeviceRequest = (
  docRequests: Array<{ docType?: string; namespaces: Record<string, Record<string, boolean>> }>
) =>
  DeviceRequest.create({
    docRequests: docRequests.map(({ docType, namespaces }) =>
      DocRequest.create({ itemsRequest: ItemsRequest.create({ docType: docType ?? mdlDocType, namespaces }) })
    ),
  })

/**
 * A device request for more than two age_over_NN elements in a namespace, which `ItemsRequest.create`
 * refuses, so the items request is built from its structure as a decoded request would be.
 */
const createAgeOverDeviceRequest = (ageOver: Record<string, boolean>) =>
  DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.fromEncodedStructure(
          new Map<unknown, unknown>([
            ['docType', mdlDocType],
            ['nameSpaces', new Map([[mdlNamespace, new Map(Object.entries({ family_name: true, ...ageOver }))]])],
          ])
        ),
      }),
    ],
  })

const deviceNamespaces = (values: Record<string, Record<string, unknown>>) =>
  DeviceNamespaces.create({
    deviceNamespaces: new Map(
      Object.entries(values).map(([namespace, elements]) => [
        namespace,
        DeviceSignedItems.create({ deviceSignedItems: new Map(Object.entries(elements)) }),
      ])
    ),
  })

describe('Holder.matchDeviceRequest', () => {
  test('a credential containing every requested element matches in full', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false } } },
    ])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ docType: photoIdDocType }), await createIssuerSigned()],
    })

    expect(match.success).toBe(true)

    const [docRequest] = match.docRequests
    expect(docRequest).toMatchObject({ docRequestIndex: 0, docType: mdlDocType, success: true })
    expect(docRequest.validCredentials).toStrictEqual([
      {
        credentialIndex: 1,
        success: true,
        docType: { success: true, docType: mdlDocType },
        claims: {
          success: true,
          validClaims: [
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
          ],
          failedClaims: [],
        },
      },
    ])

    // The credential of another docType fails on its docType.
    expect(docRequest.failedCredentials).toHaveLength(1)
    expect(docRequest.failedCredentials[0]).toMatchObject({
      credentialIndex: 0,
      success: false,
      docType: {
        success: false,
        docType: photoIdDocType,
        reason: `Credential has docType '${photoIdDocType}', but docType '${mdlDocType}' was requested`,
      },
    })
  })

  test('a credential of the requested docType reports the claims it is missing', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    const match = Holder.matchDeviceRequest({ deviceRequest, credentials: [await createIssuerSigned()] })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].validCredentials).toStrictEqual([])

    // "You have this credential, but these claims are missing"
    const [credentialMatch] = match.docRequests[0].failedCredentials
    expect(credentialMatch).toMatchObject({ success: false, docType: { success: true }, claims: { success: false } })
    expect(credentialMatch.claims.validClaims.map((claim) => claim.elementIdentifier)).toStrictEqual(['family_name'])
    expect(credentialMatch.claims.failedClaims).toStrictEqual([
      {
        success: false,
        namespace: mdlNamespace,
        elementIdentifier: 'portrait',
        intentToRetain: true,
        optional: false,
        failure: 'notDisclosed',
        reason: `Element 'portrait' in namespace '${mdlNamespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
      },
    ])
  })

  test('an age_over_NN request is answered by the age attestation 18013-5 7.2.5 allows', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ claims: { age_over_21: true } })],
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[0]).toMatchObject({
      success: true,
      elementIdentifier: 'age_over_18',
      disclosedElementIdentifier: 'age_over_21',
      elementValue: true,
    })
  })

  test('an element that is not issuer-signed but the device key is authorized for is disclosed device-signed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        {
          issuerSigned: await createIssuerSigned({
            keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
          }),
          deviceNamespaces: deviceNamespaces({ [deviceNamespace]: { session_id: 'abc' } }),
        },
      ],
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[1]).toStrictEqual({
      success: true,
      namespace: deviceNamespace,
      elementIdentifier: 'session_id',
      intentToRetain: false,
      optional: false,
      disclosedElementIdentifier: 'session_id',
      elementValue: 'abc',
      source: 'deviceSigned',
    })
  })

  test('an element the device key is authorized for is missing when no value is provided for it', async () => {
    // Authorizing the device key for the whole namespace (18013-5 9.1.2.4) does not give the holder
    // a value for every element in it.
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])
    const issuerSigned = await createIssuerSigned({
      keyAuthorizations: KeyAuthorizations.create({ namespaces: [mdlNamespace] }),
    })

    const match = Holder.matchDeviceRequest({ deviceRequest, credentials: [issuerSigned] })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].failedCredentials[0].claims.failedClaims).toStrictEqual([
      {
        success: false,
        namespace: mdlNamespace,
        elementIdentifier: 'portrait',
        intentToRetain: true,
        optional: false,
        failure: 'notDisclosed',
        reason: `Element 'portrait' in namespace '${mdlNamespace}' is not issuer-signed in the credential, so it has to be disclosed device-signed, but no value was provided for it in the device namespaces`,
      },
    ])

    // Creating the response fails for the same reason.
    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new MissingRequestedElementError(match.docRequests[0].failedCredentials[0].claims.failedClaims[0].reason)
    )
  })

  test('a device-signed value the device key is not authorized for does not match', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [deviceNamespace]: { session_id: false } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        {
          issuerSigned: await createIssuerSigned(),
          deviceNamespaces: deviceNamespaces({ [deviceNamespace]: { session_id: 'abc' } }),
        },
      ],
    })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].failedCredentials[0].claims.failedClaims[0]).toMatchObject({
      failure: 'notDisclosed',
      reason: `Element 'session_id' in namespace '${deviceNamespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
    })
  })

  test('an age_over_NN request is not answered with a device-signed value for another age', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { age_over_18: true } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        {
          issuerSigned: await createIssuerSigned({
            keyAuthorizations: KeyAuthorizations.create({ namespaces: [mdlNamespace] }),
          }),
          // Device-signed values are the holder's own, so only one for age_over_18 itself answers it.
          deviceNamespaces: deviceNamespaces({ [mdlNamespace]: { age_over_21: true } }),
        },
      ],
    })

    expect(match.success).toBe(false)
    expect(match.docRequests[0].failedCredentials[0].claims.failedClaims[0]).toMatchObject({
      elementIdentifier: 'age_over_18',
      failure: 'notDisclosed',
    })
  })

  test('a doc request for more than two age_over_NN elements in a namespace is invalid (18013-5 7.2.5)', async () => {
    const deviceRequest = createAgeOverDeviceRequest({ age_over_18: false, age_over_21: false, age_over_65: false })

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ claims: { age_over_18: true, age_over_21: true, age_over_65: false } })],
    })

    expect(match).toStrictEqual({
      success: false,
      docRequestsAsAlternatives: false,
      docRequests: [
        {
          docRequestIndex: 0,
          docType: mdlDocType,
          success: false,
          validCredentials: [],
          failedCredentials: [],
          invalidDocRequest: {
            failure: 'ageOverLimitExceeded',
            reason: `Doc request 0 requests 'age_over_18', 'age_over_21', 'age_over_65' in namespace '${mdlNamespace}', but at most two age_over_NN elements may be requested per namespace`,
          },
        },
      ],
    })
  })

  test('multiple doc requests can be matched as alternatives, of which at least one has to be answered', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true } } },
      { docType: photoIdDocType, namespaces: { [mdlNamespace]: { family_name: true } } },
    ])
    const credentials = [await createIssuerSigned()]

    const allMatch = Holder.matchDeviceRequest({ deviceRequest, credentials })
    expect(allMatch).toMatchObject({ success: false, docRequestsAsAlternatives: false })

    const alternativesMatch = Holder.matchDeviceRequest({
      deviceRequest,
      credentials,
      treatAmbiguousMultipleDocRequestsAsAlternatives: true,
    })
    expect(alternativesMatch).toMatchObject({ success: true, docRequestsAsAlternatives: true })
    expect(alternativesMatch.docRequests.map((docRequest) => docRequest.success)).toEqual([true, false])

    const noneMatch = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [await createIssuerSigned({ docType: 'org.example.other' })],
      treatAmbiguousMultipleDocRequestsAsAlternatives: true,
    })
    expect(noneMatch).toMatchObject({ success: false, docRequestsAsAlternatives: true })
  })

  test('ItemsRequest.create refuses more than two age_over_NN elements in a namespace', () => {
    expect(() =>
      createDeviceRequest([
        { namespaces: { [mdlNamespace]: { age_over_18: false, age_over_21: false, age_over_65: false } } },
      ])
    ).toThrow(AgeOverLimitExceededError)

    // Two per namespace, in more than one namespace, is allowed.
    expect(() =>
      createDeviceRequest([
        {
          namespaces: {
            [mdlNamespace]: { age_over_18: false, age_over_21: false },
            'org.iso.18013.5.1.US': { age_over_18: false, age_over_21: false },
          },
        },
      ])
    ).not.toThrow()
  })

  test('an issuer-signed element is disclosed issuer-signed, also when the device key is authorized for it', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    const match = Holder.matchDeviceRequest({
      deviceRequest,
      credentials: [
        await createIssuerSigned({ keyAuthorizations: KeyAuthorizations.create({ namespaces: [mdlNamespace] }) }),
      ],
    })

    const [docRequest] = match.docRequests
    assert(docRequest.success)
    expect(docRequest.validCredentials[0].claims.validClaims[0]).toMatchObject({
      source: 'issuerSigned',
      elementValue: 'Doe',
    })
  })
})

describe('creating a response from a holder match', () => {
  test('a response for a credential that matched in full satisfies the verifier match', async () => {
    const deviceRequest = createDeviceRequest([
      {
        namespaces: {
          [mdlNamespace]: { family_name: true, age_over_18: true },
          [deviceNamespace]: { session_id: false },
        },
      },
    ])
    const credential = {
      issuerSigned: await createIssuerSigned({
        claims: { age_over_21: true },
        keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
      }),
      deviceNamespaces: deviceNamespaces({ [deviceNamespace]: { session_id: 'abc' } }),
    }

    const holderMatch = Holder.matchDeviceRequest({ deviceRequest, credentials: [credential] })
    expect(holderMatch.success).toBe(true)

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [{ ...credential, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
      },
      mdocContext
    )

    const verifierMatch = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [deviceNamespace]: { '*': { source: 'deviceSigned' } } } }],
      },
    })

    expect(verifierMatch.success).toBe(true)
    const [verifierDocRequest] = verifierMatch.docRequests
    assert(verifierDocRequest.success)
    const [document] = verifierDocRequest.validDocuments
    expect(document.claims.unrequestedClaims).toStrictEqual([])

    // Both sides report the same claims.
    const [holderDocRequest] = holderMatch.docRequests
    assert(holderDocRequest.success)
    expect(document.claims.validClaims).toStrictEqual(holderDocRequest.validCredentials[0].claims.validClaims)
  })

  test('a device-signed element needs a value in the device namespaces', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [deviceNamespace]: { session_id: false } } }])
    const issuerSigned = await createIssuerSigned({
      keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
    })

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new MissingRequestedElementError(
        `Element 'session_id' in namespace '${deviceNamespace}' is not issuer-signed in the credential, so it has to be disclosed device-signed, but no value was provided for it in the device namespaces`
      )
    )
  })

  test('a requested element that is neither issuer-signed nor authorized cannot be disclosed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, portrait: true } } },
    ])

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            { issuerSigned: await createIssuerSigned(), docRequestIndex: 0, signature: { signingKey: deviceKey } },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(MissingRequestedElementError)
  })

  test('elements selects which requested elements are disclosed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, given_name: false, portrait: true } } },
    ])

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned(),
            docRequestIndex: 0,
            elements: { [mdlNamespace]: ['family_name'] },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [
          {
            docRequestIndex: 0,
            elements: { [mdlNamespace]: { given_name: { optional: true }, portrait: { optional: true } } },
          },
        ],
      },
    })

    expect(match.success).toBe(true)
    const [docRequest] = match.docRequests
    assert(docRequest.success)
    const { claims } = docRequest.validDocuments[0]
    expect(claims.validClaims.map((claim) => claim.elementIdentifier)).toEqual(['family_name'])
    expect(claims.failedClaims.map((claim) => claim.elementIdentifier)).toEqual(['given_name', 'portrait'])
  })

  test('only selected requested elements are disclosed device-signed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false, nonce: false } } },
    ])

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned({
              keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
            }),
            docRequestIndex: 0,
            // The user declined to share session_id, and transaction_id is not requested.
            elements: { [mdlNamespace]: ['family_name'], [deviceNamespace]: ['nonce'] },
            deviceNamespaces: deviceNamespaces({
              [deviceNamespace]: { session_id: 'abc', nonce: 'def', transaction_id: 'ghi' },
            }),
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    const [document] = deviceResponse.documents ?? []
    expect(document.deviceSigned.deviceNamespaces.deviceNamespaces).toStrictEqual(
      deviceNamespaces({ [deviceNamespace]: { nonce: 'def' } }).deviceNamespaces
    )

    // Device auth covers the disclosed device namespaces, not the ones provided.
    const checks: Array<VerificationAssessment> = []
    await deviceResponse.verify(
      {
        sessionTranscript,
        trustedCertificates: [],
        disableCertificateChainValidation: true,
        onCheck: (check) => checks.push(check),
      },
      mdocContext
    )
    const deviceAuthChecks = checks.filter((check) => check.category === 'DEVICE_AUTH')
    expect(deviceAuthChecks.some((check) => check.status === 'PASSED')).toBe(true)
    expect(deviceAuthChecks.filter((check) => check.status === 'FAILED')).toStrictEqual([])
  })

  test('an element that is not requested cannot be selected', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned(),
              docRequestIndex: 0,
              elements: { [mdlNamespace]: ['family_name', 'birth_date'] },
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new InvalidElementSelectionError(
        `Element 'birth_date' in namespace '${mdlNamespace}' is selected for disclosure, but the doc request does not request it`
      )
    )
  })

  test('namespaces and element identifiers that are Object.prototype properties are used as they are', async () => {
    // Typed as a plain namespace, as TypeScript types a `constructor` key after `Object.prototype`.
    const prototypeNamespace: string = 'constructor'
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [prototypeNamespace]: { toString: false } } },
    ])
    const credential = {
      issuerSigned: await createIssuerSigned({
        keyAuthorizations: KeyAuthorizations.create({ namespaces: [prototypeNamespace] }),
      }),
      deviceNamespaces: deviceNamespaces({ [prototypeNamespace]: { toString: 'abc' } }),
    }

    // Leaving the `constructor` namespace out of `elements` does not disclose it.
    const withoutConstructor = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            ...credential,
            docRequestIndex: 0,
            elements: { [mdlNamespace]: ['family_name'] },
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )
    expect(withoutConstructor.documents?.[0].deviceSigned.deviceNamespaces.deviceNamespaces.size).toBe(0)

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [{ ...credential, docRequestIndex: 0, signature: { signingKey: deviceKey } }],
      },
      mdocContext
    )

    // `'*'` applies to `toString`, which is not named explicitly.
    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [{ docRequestIndex: 0, elements: { [prototypeNamespace]: { '*': { source: 'deviceSigned' } } } }],
      },
    })
    expect(match.success).toBe(true)
  })

  test('age requests answered with the same age attestation are selected together', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true, age_over_18: false, age_over_21: false } } },
    ])
    // Both requests are answered with age_over_21 (18013-5 7.2.5).
    const issuerSigned = await createIssuerSigned({ claims: { age_over_21: true } })

    const createResponse = (elements: Record<string, Array<string>>) =>
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [{ issuerSigned, docRequestIndex: 0, elements, signature: { signingKey: deviceKey } }],
        },
        mdocContext
      )
    const disclosed = async (elements: Record<string, Array<string>>) =>
      (await createResponse(elements)).documents?.[0].issuerSigned
        .getIssuerNamespace(mdlNamespace)
        ?.map((item) => item.elementIdentifier)

    // Leaving out either one would still disclose its answer through the other.
    await expect(createResponse({ [mdlNamespace]: ['family_name', 'age_over_18'] })).rejects.toThrow(
      new InvalidElementSelectionError(
        `Element 'age_over_18' in namespace '${mdlNamespace}' is selected for disclosure, but it is answered with 'age_over_21', which also answers 'age_over_21' that is not selected. Select both or neither`
      )
    )
    await expect(createResponse({ [mdlNamespace]: ['family_name', 'age_over_21'] })).rejects.toThrow(
      new InvalidElementSelectionError(
        `Element 'age_over_21' in namespace '${mdlNamespace}' is selected for disclosure, but it is answered with 'age_over_21', which also answers 'age_over_18' that is not selected. Select both or neither`
      )
    )

    expect(await disclosed({ [mdlNamespace]: ['family_name', 'age_over_18', 'age_over_21'] })).toEqual([
      'family_name',
      'age_over_21',
    ])
    expect(await disclosed({ [mdlNamespace]: ['family_name'] })).toEqual(['family_name'])
  })

  test('at most two age_over_NN elements are disclosed in a namespace (18013-5 7.2.5)', async () => {
    const deviceRequest = createAgeOverDeviceRequest({ age_over_18: false, age_over_21: false, age_over_65: false })
    const createResponse = async (claims: Record<string, boolean>, elements?: Record<string, Array<string>>) =>
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned({ claims }),
              docRequestIndex: 0,
              elements,
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )

    // Answering every request would disclose three age attestations.
    await expect(createResponse({ age_over_18: true, age_over_21: true, age_over_65: false })).rejects.toThrow(
      new AgeOverLimitExceededError(
        `Doc request would be answered with 'age_over_18', 'age_over_21', 'age_over_65' in namespace '${mdlNamespace}', but at most two age_over_NN elements may be disclosed per namespace. Select at most two of them`
      )
    )

    // Selecting two of them is allowed.
    const selected = await createResponse(
      { age_over_18: true, age_over_21: true, age_over_65: false },
      { [mdlNamespace]: ['family_name', 'age_over_18', 'age_over_65'] }
    )
    expect(
      selected.documents?.[0].issuerSigned.getIssuerNamespace(mdlNamespace)?.map((item) => item.elementIdentifier)
    ).toEqual(['family_name', 'age_over_18', 'age_over_65'])

    // Only distinct disclosed attestations count: age_over_18 and age_over_21 are both answered with
    // age_over_21.
    const substituted = await createResponse({ age_over_21: true, age_over_65: false })
    expect(
      substituted.documents?.[0].issuerSigned.getIssuerNamespace(mdlNamespace)?.map((item) => item.elementIdentifier)
    ).toEqual(['family_name', 'age_over_21', 'age_over_65'])
  })

  test('the issuer-signed namespaces are left out when only device-signed elements are disclosed', async () => {
    const deviceRequest = createDeviceRequest([
      { namespaces: { [mdlNamespace]: { family_name: true }, [deviceNamespace]: { session_id: false } } },
    ])

    const deviceResponse = await DeviceResponse.createWithDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        documents: [
          {
            issuerSigned: await createIssuerSigned({
              keyAuthorizations: KeyAuthorizations.create({ namespaces: [deviceNamespace] }),
            }),
            docRequestIndex: 0,
            elements: { [deviceNamespace]: ['session_id'] },
            deviceNamespaces: deviceNamespaces({ [deviceNamespace]: { session_id: 'abc' } }),
            signature: { signingKey: deviceKey },
          },
        ],
      },
      mdocContext
    )

    // 18013-5 8.3.2.1.2.2: `IssuerNameSpaces` must have at least one namespace, so `nameSpaces` is
    // left out rather than encoded as an empty map.
    const [document] = DeviceResponse.decode(deviceResponse.encode()).documents ?? []
    expect(document.issuerSigned.issuerNamespaces).toBeUndefined()
    expect(document.issuerSigned.encodedStructure.has('nameSpaces')).toBe(false)

    const match = Verifier.matchDeviceRequest({
      deviceRequest,
      deviceResponse,
      matchOptions: {
        docRequests: [
          {
            docRequestIndex: 0,
            elements: {
              [mdlNamespace]: { family_name: { optional: true } },
              [deviceNamespace]: { '*': { source: 'deviceSigned' } },
            },
          },
        ],
      },
    })
    expect(match.success).toBe(true)
  })

  test('a credential of another docType cannot answer a doc request', async () => {
    const deviceRequest = createDeviceRequest([{ namespaces: { [mdlNamespace]: { family_name: true } } }])

    await expect(
      DeviceResponse.createWithDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          documents: [
            {
              issuerSigned: await createIssuerSigned({ docType: photoIdDocType }),
              docRequestIndex: 0,
              signature: { signingKey: deviceKey },
            },
          ],
        },
        mdocContext
      )
    ).rejects.toThrow(
      new DocTypeMismatchError(
        `Credential has docType '${photoIdDocType}', but doc request 0 requests docType '${mdlDocType}'`
      )
    )
  })
})
