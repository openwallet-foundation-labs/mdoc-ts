import { describe, it } from 'vitest'
import { IssuerSigned } from '../../../src'
import { mdocContext } from '../../context'
import { issuerCertificate } from './issuerCertificate'
import { issuerSignedBytes } from './issuerSigned'

describe('BDR mDL implementation', () => {
  it('should verify mDL IssuerSigned from BDR', async () => {
    const issuerSigned = IssuerSigned.decode(issuerSignedBytes)

    await issuerSigned.issuerAuth.verify(
      {
        trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
        disableCertificateChainValidation: false,
        now: new Date('2026-01-01'),
      },
      mdocContext
    )
  })
})
