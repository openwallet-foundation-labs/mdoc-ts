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
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const readerAuthentication =
      options.readerAuthentication instanceof ReaderAuthentication
        ? options.readerAuthentication
        : new ReaderAuthentication(options.readerAuthentication)

    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'READER_AUTH')

    this.detachedPayload = readerAuthentication.encode({ asDataItem: true })

    const isValid = await this.verifySignature({}, { verify: ctx.cose.sign1.verify, x509: ctx.x509 })

    onCheck({
      status: isValid ? 'PASSED' : 'FAILED',
      check: 'Signature is invalid on the reader auth',
      reason: 'Signature is invalid on the reader auth',
    })
  }

  public static create(options: ReaderAuthOptions) {
    return super.create(options) as ReaderAuth
  }
}
