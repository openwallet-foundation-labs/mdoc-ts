import { MediaTypes, StatusList, StatusListCwt, StatusListInfo, StatusType } from '@owf/token-status-list'
import { X509Certificate } from '@peculiar/x509'
import nock from 'nock'
import { expect, suite, test } from 'vitest'
import z from 'zod'
import {
  CoseKey,
  DeviceKey,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  Holder,
  Issuer,
  IssuerSigned,
  ItemsRequest,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  SessionTranscript,
  SignatureAlgorithm,
  Status,
  //StatusListInfo,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import {
  DEVICE_JWK_PRIVATE,
  DEVICE_JWK_PUBLIC,
  INVALID_CERTIFICATE,
  ISSUER_CERTIFICATE,
  ISSUER_PRIVATE_KEY_JWK,
} from '../config'
import { mdocContext } from '../context'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

const validTrustedCertificates = [
  {
    issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    status: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
  },
]

const invalidTrustedCertificates = [
  {
    issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    status: [new Uint8Array(new X509Certificate(INVALID_CERTIFICATE).rawData)],
  },
]

const emptyTrustedCertificates = [
  {
    issuance: [],
    status: [],
  },
]

const emptyStatusTrustedCertificates = [
  {
    issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    status: [],
  },
]

suite('Verification', () => {
  test('Verify simple mdoc', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    const result = await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse: decodedDeviceResponse,
        sessionTranscript: fakeSessionTranscript,
        trustedCertificates: validTrustedCertificates,
      },
      mdocContext
    )

    expect(result).toHaveLength(1)
    const [{ document, trustedIssuanceChain, statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain }] = result
    expect(document).toBeDefined()
    expect(trustedIssuanceChain).toHaveLength(1)
    expect(trustedIssuanceChain[0]).toEqual(new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData))
    expect(statusList).toBeUndefined()
    expect(trustedStatusListChain).toBeUndefined()
    expect(identifierList).toBeUndefined()
    expect(trustedIdentifierListChain).toBeUndefined()
  })

  test('Verify mdoc with selective disclosure', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      middle_name: 'Middle',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    expect(deviceResponse.documents?.[0].issuerSigned.getPrettyClaims('org.iso.18013.5.1.mDL')).toMatchObject({
      first_name: 'First',
      last_name: 'Last',
    })

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    await expect(
      Verifier.verifyDeviceResponse(
        {
          deviceRequest,
          deviceResponse: decodedDeviceResponse,
          sessionTranscript: fakeSessionTranscript,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('Verify with custom session transcript', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    class CustomHandover extends Handover<null> {
      static get encodingSchema() {
        return z.null()
      }
    }
    const fakeSessionTranscript = SessionTranscript.create({
      handover: CustomHandover.fromEncodedStructure(null),
    })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    await expect(
      Verifier.verifyDeviceResponse(
        {
          deviceRequest,
          deviceResponse: decodedDeviceResponse,
          sessionTranscript: fakeSessionTranscript,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('Verify mdoc with status status_list check', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/10'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/10')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    const result = await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse: decodedDeviceResponse,
        sessionTranscript: fakeSessionTranscript,
        trustedCertificates: validTrustedCertificates,
      },
      mdocContext
    )

    expect(result).toHaveLength(1)
    const [{ document, trustedIssuanceChain, statusList: resultStatusList, trustedStatusListChain, identifierList, trustedIdentifierListChain }] = result
    expect(document).toBeDefined()
    expect(trustedIssuanceChain).toHaveLength(1)
    expect(trustedIssuanceChain[0]).toEqual(new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData))
    expect(trustedStatusListChain?.[0]).toEqual(new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData))
    expect(resultStatusList).toBeDefined()
    expect(identifierList).toBeUndefined()
    expect(trustedIdentifierListChain).toBeUndefined()
  })

  test('Verify mdoc with status status_list check with trusted certificates', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/10'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/10')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    await Verifier.verifyDeviceResponse(
      {
        deviceRequest,
        deviceResponse: decodedDeviceResponse,
        sessionTranscript: fakeSessionTranscript,
        trustedCertificates: validTrustedCertificates,
      },
      mdocContext
    )
  })

  test('Verify mdoc with status status_list invalid status list format of JWT', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/30'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/30')
      .reply(200, 'invalid-jwt', { 'Content-Type': MediaTypes.StatusListJwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow(
      'Could not verify status list token. @owf/mdoc currently does not support JWT format for status list, only CWT'
    )
  })

  test('Verify mdoc with status invalid no trusted certificates supplied', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/40'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )
    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/40')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: emptyTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow('No trusted certificate was found while validating the X.509 chain')
  })

  test('Verify mdoc with status status_list invalid no trusted status certificates supplied', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/40'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )
    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/40')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: emptyStatusTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow(
      'Atleast one certificate is required to check the status of the mdoc. Make sure to supply them in the `trustedStatusCertificates` option'
    )
  })

  test('Verify mdoc with status status_list check with invalid trusted certificates', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/10'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/10')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: invalidTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow('No trusted certificate was found while validating the X.509 chain')
  })

  test('Verify mdoc with status status_list check while credential is suspended', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/20'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = new StatusListCwt({
      payload: { statusList, subject: uri },
      protectedHeaders: ProtectedHeaders.create({
        protectedHeaders: new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.X5Chain, [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)]],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
        ]),
      }),
    })
    statusListCwt.updateStatusList(idx, StatusType.Suspended)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+cwt/)
      .persist()
      .get('/status-list/20')
      .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })

    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: { statusList: { idx: 3, uri } },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow(`Status for id '3' is not Valid (0), but is instead '2'`)
  })

  test('Fail to create mdoc with not enough attributes', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                middle_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    await expect(
      Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          issuerSigned: [credential],
          sessionTranscript: fakeSessionTranscript,
          signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('Verify with skewSeconds allows time difference', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    // Create a credential that is valid from 5 minutes in the future
    const now = new Date()
    const validFromFuture = new Date(now.getTime() + 5 * 60 * 1000) // 5 minutes in future
    const validUntilFuture = new Date(validFromFuture.getTime() + 30 * 365 * 24 * 60 * 60 * 1000) // 30 years

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom: validFromFuture, validUntil: validUntilFuture },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci
    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    // Verification should fail with default skew (30 seconds)
    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
          now,
        },
        mdocContext
      )
    ).rejects.toThrow()

    // Verification should succeed with 10 minutes skew (600 seconds)
    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
          now,
          skewSeconds: 600,
        },
        mdocContext
      )
    ).resolves.toBeDefined()
  })

  test('Fail to verify with not matching device request', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)

    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      first_name: 'First',
      last_name: 'Last',
    })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    const encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    // openid4vci protocol

    const credential = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: credential,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    const deviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    const fakeSessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'my-client-id',
        responseUri: 'my-response-uri.com',
        nonce: 'my-random-nonce',
      },
      mdocContext
    )

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        issuerSigned: [credential],
        sessionTranscript: fakeSessionTranscript,
        signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
      },
      mdocContext
    )

    const encodedDeviceResponse = deviceResponse.encodedForOid4Vp

    // openid4vp protocol

    const decodedDeviceResponse = DeviceResponse.fromEncodedForOid4Vp(encodedDeviceResponse)

    const newDeviceRequest = DeviceRequest.create({
      docRequests: [
        DocRequest.create({
          itemsRequest: ItemsRequest.create({
            docType: 'org.iso.18013.5.1',
            namespaces: {
              'org.iso.18013.5.1.mDL': {
                first_name: true,
                middle_name: true,
                last_name: true,
              },
            },
          }),
        }),
      ],
    })

    await expect(
      Verifier.verifyDeviceResponse(
        {
          deviceRequest: newDeviceRequest,
          deviceResponse: decodedDeviceResponse,
          sessionTranscript: fakeSessionTranscript,
          trustedCertificates: validTrustedCertificates,
        },
        mdocContext
      )
    ).rejects.toThrow()
  })

  test('Issue mdoc with embedded Status (status_list)', async () => {
    const issuer = new Issuer('org.iso.18013.5.1', mdocContext)
    issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', { first_name: 'First', last_name: 'Last' })

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
      status: Status.create({
        statusList: StatusListInfo.create({ uri: 'https://issuer.example/status/1', idx: 42 }),
      }),
    })

    // Verify the signed credential still validates end-to-end.
    await expect(
      Holder.verifyIssuerSigned(
        {
          issuerSigned: IssuerSigned.fromEncodedForOid4Vci(issuerSigned.encodedForOid4Vci),
          trustedCertificates: validTrustedCertificates,
          disableStatusValidation: true,
        },
        mdocContext
      )
    ).resolves.toBeDefined()

    // The Status payload survived signing + decode.
    const mso = issuerSigned.issuerAuth.mobileSecurityObject
    expect(mso.status).toBeInstanceOf(Status)
    expect(mso.status?.statusList?.uri).toBe('https://issuer.example/status/1')
    expect(mso.status?.statusList?.idx).toBe(42)
  })

  // Regression tests for status-certificate selection across multiple trusted-certificate
  // entries. After the issuer chain validates, the verifier must pick the `status` certs from
  // the SAME entry whose `issuance` certs actually anchored the chain — not just the first entry.
  // A previous `.map()` (instead of `.some()`) always returned a truthy array, so `find()` matched
  // the first entry unconditionally and the wrong `status` certificates were used. These tests use
  // more than one entry so the wrong-entry behaviour is observable; with a single entry both
  // implementations happen to agree.
  suite('Status certificate selection across multiple trusted certificates', () => {
    const idx = 3
    const issuerCert = new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)
    const otherCert = new Uint8Array(new X509Certificate(INVALID_CERTIFICATE).rawData)

    // Signs a valid status-list CWT (signer = the issuer key, chain = the issuer cert) where the
    // credential's index is Valid, and serves it from `uri`.
    const mockValidStatusList = async (uri: string, path: string) => {
      const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
      const statusListCwt = new StatusListCwt({
        payload: { statusList, subject: uri },
        protectedHeaders: ProtectedHeaders.create({
          protectedHeaders: new Map<number, unknown>([
            [RegisteredCwtHeaderClaimKey.X5Chain, [issuerCert]],
            [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          ]),
        }),
      })
      statusListCwt.updateStatusList(idx, StatusType.Valid)
      const encodedCwt = await statusListCwt.signAndEncode(
        { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
        { sign: mdocContext.cose.sign1.sign }
      )

      nock('https://example.org')
        .matchHeader('Accept', /application\/statuslist\+cwt/)
        .persist()
        .get(path)
        .reply(200, Buffer.from(encodedCwt), { 'Content-Type': MediaTypes.StatusListCwt })
    }

    const signCredentialWithStatus = async (uri: string) => {
      const issuer = new Issuer('org.iso.18013.5.1', mdocContext)
      issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', { first_name: 'First', last_name: 'Last' })

      const issuerSigned = await issuer.sign({
        signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
        certificates: [issuerCert],
        algorithm: SignatureAlgorithm.ES256,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
        validityInfo: { signed, validFrom, validUntil },
        status: { statusList: { idx, uri } },
      })

      return IssuerSigned.fromEncodedForOid4Vci(issuerSigned.encodedForOid4Vci)
    }

    test('selects the status certs from the entry whose issuance anchored the chain (matching entry is not first)', async () => {
      const uri = 'https://example.org/status-list/50'
      await mockValidStatusList(uri, '/status-list/50')
      const credential = await signCredentialWithStatus(uri)

      // The first entry does NOT contain the chain's root in `issuance`, and carries a `status` cert
      // that cannot verify the status-list CWT. Only the second entry actually anchors the chain and
      // carries the correct `status` cert. The verifier must skip the first entry and use the second.
      const trustedCertificates = [
        { issuance: [otherCert], status: [otherCert] },
        { issuance: [issuerCert], status: [issuerCert] },
      ]

      await expect(
        Holder.verifyIssuerSigned({ issuerSigned: credential, trustedCertificates }, mdocContext)
      ).resolves.toBeDefined()
    })

    test('does not borrow status certs from an earlier, non-matching entry', async () => {
      const uri = 'https://example.org/status-list/51'
      await mockValidStatusList(uri, '/status-list/51')
      const credential = await signCredentialWithStatus(uri)

      // Inverse of the test above: the first entry has the correct `status` cert but its `issuance`
      // does NOT anchor the chain. The matching (second) entry has a `status` cert that cannot verify
      // the status-list CWT. Selecting by the first entry would wrongly succeed; the matching entry
      // must be used, so status validation fails.
      const trustedCertificates = [
        { issuance: [otherCert], status: [issuerCert] },
        { issuance: [issuerCert], status: [otherCert] },
      ]

      await expect(
        Holder.verifyIssuerSigned({ issuerSigned: credential, trustedCertificates }, mdocContext)
      ).rejects.toThrow('No trusted certificate was found while validating the X.509 chain')
    })
  })
})
