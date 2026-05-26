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
  SessionTranscript,
  SignatureAlgorithm,
  Status,
  //StatusListInfo,
  Verifier,
} from '../../src'
import { Handover } from '../../src/mdoc/models/handover'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      },
      mdocContext
    )
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })

  test('Verify mdoc with status status_list check', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/10'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = StatusListCwt.createFromStatusListAndSubject(statusList, uri)
    statusListCwt.updateStatusList(idx, StatusType.Valid)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+(cwt|jwt),application\/statuslist\+(cwt|jwt)/)
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      },
      mdocContext
    )
  })

  test('Verify mdoc with status status_list check while credential is suspended', async () => {
    const idx = 3
    const uri = 'https://example.org/status-list/20'
    const statusList = new StatusList(new Array(10).fill(StatusType.Invalid), 2)
    const statusListCwt = StatusListCwt.createFromStatusListAndSubject(statusList, uri)
    statusListCwt.updateStatusList(idx, StatusType.Suspended)
    const encodedCwt = await statusListCwt.signAndEncode(
      { signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK), algorithm: SignatureAlgorithm.ES256 },
      { sign: mdocContext.cose.sign1.sign }
    )

    nock('https://example.org')
      .matchHeader('Accept', /application\/statuslist\+(cwt|jwt),application\/statuslist\+(cwt|jwt)/)
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          now,
          skewSeconds: 600,
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
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
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          disableStatusValidation: true,
        },
        mdocContext
      )
    ).resolves.toBeUndefined()

    // The Status payload survived signing + decode.
    const mso = issuerSigned.issuerAuth.mobileSecurityObject
    expect(mso.status).toBeInstanceOf(Status)
    expect(mso.status?.statusList?.uri).toBe('https://issuer.example/status/1')
    expect(mso.status?.statusList?.idx).toBe(42)
  })
})
