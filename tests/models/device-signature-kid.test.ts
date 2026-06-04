import { X509Certificate } from '@peculiar/x509'
import { expect, suite, test } from 'vitest'
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
  RegisteredCwtHeaderClaimKey,
  SessionTranscript,
  SignatureAlgorithm,
  Verifier,
} from '../../src'
import { DEVICE_JWK_PRIVATE, DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

const trustedCertificates = [
  {
    issuance: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    status: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
  },
]

/** Issue an mdoc and present it, returning the decoded DeviceResponse and the session transcript. */
async function presentMdoc() {
  const issuer = new Issuer('org.iso.18013.5.1', mdocContext)
  issuer.addIssuerNamespace('org.iso.18013.5.1.mDL', { first_name: 'First', last_name: 'Last' })

  const issuerSigned = await issuer.sign({
    signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
    validityInfo: { signed, validFrom, validUntil },
  })

  const credential = IssuerSigned.fromEncodedForOid4Vci(issuerSigned.encodedForOid4Vci)

  const deviceRequest = DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({
          docType: 'org.iso.18013.5.1',
          namespaces: { 'org.iso.18013.5.1.mDL': { first_name: true, last_name: true } },
        }),
      }),
    ],
  })

  const sessionTranscript = await SessionTranscript.forOid4Vp(
    { clientId: 'my-client-id', responseUri: 'my-response-uri.com', nonce: 'my-random-nonce' },
    mdocContext
  )

  // DEVICE_JWK_PRIVATE intentionally has no `kid`, so the device key's keyId is undefined.
  const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
    {
      deviceRequest,
      issuerSigned: [credential],
      sessionTranscript,
      signature: { signingKey: CoseKey.fromJwk(DEVICE_JWK_PRIVATE) },
    },
    mdocContext
  )

  const decoded = DeviceResponse.fromEncodedForOid4Vp(deviceResponse.encodedForOid4Vp)
  return { decoded, deviceRequest, sessionTranscript }
}

suite('deviceSignature kid header', () => {
  test('a device key without a keyId produces no kid header (no { 4: undefined })', async () => {
    const { decoded, deviceRequest, sessionTranscript } = await presentMdoc()

    const deviceSignature = decoded.documents?.[0].deviceSigned.deviceAuth.deviceSignature
    expect(deviceSignature).toBeDefined()
    expect(deviceSignature?.unprotectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.KeyId)).toBe(false)
    expect(deviceSignature?.protectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.KeyId)).toBe(false)

    // And the response still verifies end to end.
    await expect(
      Verifier.verifyDeviceResponse(
        { deviceRequest, deviceResponse: decoded, sessionTranscript, trustedCertificates },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })
})
