import { Sign1, type Sign1DecodedStructure, type Sign1EncodedStructure, type Sign1Options } from '@owf/cose'
import type { MdocContext } from '../../context'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { ReaderAuthentication, type ReaderAuthenticationOptions } from './reader-authentication'

export type ReaderAuthEncodedStructure = Sign1EncodedStructure
export type ReaderAuthDecodedStructure = Sign1DecodedStructure
export type ReaderAuthOptions = Sign1Options

export class ReaderAuth extends Sign1 {
  public async verify(
    options: {
      readerAuthentication: ReaderAuthentication | ReaderAuthenticationOptions
      verificationCallback?: VerificationCallback
      /**
       * Trust anchors for the reader's certificate chain (e.g. CAs listed in a
       * RICAL). When provided, the chain in this Sign1's x5chain header is
       * validated against these anchors per RFC 5280. When omitted, only the
       * detached signature is verified — chain trust is not established.
       */
      trustedCertificates?: Array<Uint8Array>
      now?: Date
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const readerAuthentication =
      options.readerAuthentication instanceof ReaderAuthentication
        ? options.readerAuthentication
        : new ReaderAuthentication(options.readerAuthentication)

    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'READER_AUTH')

    const isValid = await this.verifySignature(
      {
        key: await ctx.x509.getPublicKey({ certificate: this.certificate, algorithm: this.algorithm }),
        detachedPayload: readerAuthentication.encode({ asDataItem: true }),
      },
      { verify: ctx.cose.sign1.verify }
    )

    onCheck({
      status: isValid ? 'PASSED' : 'FAILED',
      check: 'Signature is invalid on the reader auth',
      reason: 'Signature is invalid on the reader auth',
    })

    if (options.trustedCertificates) {
      try {
        if (options.trustedCertificates.length === 0) {
          throw new Error('No trusted reader certificates provided.')
        }

        await ctx.x509.verifyCertificateChain({
          trustedCertificates: options.trustedCertificates,
          x5chain: this.certificateChain,
          now: options.now ?? new Date(),
        })

        onCheck({
          status: 'PASSED',
          check: 'Reader certificate chain must be trusted',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Reader certificate chain must be trusted',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }
  }

  public static create(options: ReaderAuthOptions) {
    return super.create(options) as ReaderAuth
  }
}
