import type { CoseKey } from '@owf/cose'
import { base64url } from '@owf/identity-common'
import type { MdocContext } from './context'
import {
  type DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  IssuerSigned,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'

export class Holder {
  /**
   *
   * string should be base64url encoded as defined in openid4vci
   *
   */
  public static async verifyIssuerSigned(
    options: {
      issuerSigned: Uint8Array | string | IssuerSigned
      verificationCallback?: VerificationCallback
      now?: Date
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates?: Array<Uint8Array>
      trustedRevocationCertificates?: Array<Uint8Array>
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ) {
    const issuerSigned =
      typeof options.issuerSigned === 'string'
        ? IssuerSigned.decode(base64url.decode(options.issuerSigned))
        : options.issuerSigned instanceof Uint8Array
          ? IssuerSigned.decode(options.issuerSigned)
          : options.issuerSigned

    await issuerSigned.verify(options, ctx)
  }

  public static async verifyDeviceRequest(
    options: {
      deviceRequest: Uint8Array | DeviceRequest
      sessionTranscript: Uint8Array | SessionTranscript
      verificationCallback?: VerificationCallback
      /**
       * Trust anchors for the reader's certificate chain. When provided, each
       * `DocRequest.readerAuth` chain is validated against these anchors (e.g.
       * CAs listed in a RICAL — Reader Identification CA List, defined in
       * ISO/IEC 18013-5 second edition Annex F).
       *
       * When omitted, reader-auth signatures are verified but chain trust is
       * not established — equivalent to first-edition behaviour.
       */
      trustedCertificates?: Array<Uint8Array>
      /**
       * Reference time for certificate `notBefore`/`notAfter` checks during
       * chain validation. Defaults to the current time.
       */
      now?: Date
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const deviceRequest =
      options.deviceRequest instanceof DeviceRequest
        ? options.deviceRequest
        : DeviceRequest.decode(options.deviceRequest)

    const sessionTranscript =
      options.sessionTranscript instanceof SessionTranscript
        ? options.sessionTranscript
        : SessionTranscript.decode(options.sessionTranscript)

    for (const docRequest of deviceRequest.docRequests) {
      await docRequest.readerAuth?.verify(
        {
          readerAuthentication: {
            itemsRequest: docRequest.itemsRequest,
            sessionTranscript,
          },
          verificationCallback: options.verificationCallback,
          trustedCertificates: options.trustedCertificates,
          now: options.now,
        },
        ctx
      )
    }
  }

  public static async createDeviceResponseForDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    context: Pick<MdocContext, 'cose' | 'crypto'>
  ) {
    return await DeviceResponse.createWithDeviceRequest(options, context)
  }
}
