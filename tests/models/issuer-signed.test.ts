import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { CoseKey, DeviceKey, IssuerSigned, IssuerSignedBuilder, SignatureAlgorithm } from '../../src'
import { DEVICE_JWK_PUBLIC, ISSUER_CERTIFICATE, ISSUER_PRIVATE_KEY_JWK } from '../config'
import { mdocContext } from '../context'

const signed = new Date('2023-10-24T14:55:18Z')
const validFrom = new Date(signed)
validFrom.setMinutes(signed.getMinutes() + 5)
const validUntil = new Date(signed)
validUntil.setFullYear(signed.getFullYear() + 30)

describe('Issuer signed', () => {
  let encodedIssuerSigned: string

  test('Create issuer signed and verify', async () => {
    const isb = new IssuerSignedBuilder('org.iso.18013.5.1', mdocContext)

    isb.addIssuerNamespace('org.iso.18013.5.1.mDL', {
      family_name: 'Doe',
    })

    const issuerSigned = await isb.sign({
      signingKey: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      certificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) },
      validityInfo: { signed, validFrom, validUntil },
    })

    encodedIssuerSigned = issuerSigned.encodedForOid4Vci

    expect(issuerSigned.getPrettyClaims('org.iso.18013.5.1.mDL')).toEqual({
      family_name: 'Doe',
    })

    const isSignatureValid = await issuerSigned.issuerAuth.verifySignature({}, mdocContext)

    expect(isSignatureValid).toBeTruthy()

    const issuerSignedDecoded = IssuerSigned.fromEncodedForOid4Vci(encodedIssuerSigned)

    const isSignatureValidFromDecoded = await issuerSignedDecoded.issuerAuth.verifySignature({}, mdocContext)
    expect(isSignatureValidFromDecoded).toBeTruthy()
  })
})
