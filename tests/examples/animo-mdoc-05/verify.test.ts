import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { DeviceResponse, SessionTranscript } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate, rootCertificate } from './issuerCertificate'

describe('Animo mdoc 0.5.x mdoc implementation', () => {
  test('verify DeviceResponse from Paradym Wallet (OpenID4VP 1.0) issued by Animo Playground using mdoc 0.5.x', async () => {
    const verifierGeneratedNonce = 'LMGPB6k--THpBUSkEBvLxmdMIi3Ee1fjHXXUUzBVa04'
    const clientId = 'x509_san_dns:playground.animo.id'
    const responseUri =
      'https://playground.animo.id/oid4vp/8caaebcc-d48c-471b-86b0-a534e15c4774/authorize?session=6c115dbc-1364-4e9f-a325-173eeec01a5a'

    const jwkThumbprint = Buffer.from('61a29f269176244d397cae26f7f80ab196bffcb65fe3052b540c78073dab7c1e', 'hex')

    const decoded = DeviceResponse.decode(deviceResponse)

    // Expect issuer certificate
    expect(
      new X509Certificate(decoded.documents?.[0].issuerSigned.issuerAuth.certificate).equal(issuerCertificate)
    ).toBe(true)

    await expect(
      decoded.verify(
        {
          trustedCertificates: [{ issuance: [new Uint8Array(rootCertificate.rawData)] }],
          sessionTranscript: await SessionTranscript.forOid4Vp(
            {
              clientId,
              responseUri,
              nonce: verifierGeneratedNonce,
              jwkThumbprint,
            },
            mdocContext
          ),
          now: new Date('2026-01-12'),
        },
        mdocContext
      )
    ).resolves.toBeDefined()
  })
})
