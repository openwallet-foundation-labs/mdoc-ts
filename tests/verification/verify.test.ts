import { X509Certificate } from '@peculiar/x509'
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
})
