import type { MdocContext } from './context'
import type { CoseKey } from './cose'
import {
  type DeviceNamespaces,
  DeviceRequest,
  DeviceResponse,
  IssuerSigned,
  SessionTranscript,
  type VerificationCallback,
} from './mdoc'
import { base64url } from './utils'

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
      trustedCertificates?: Array<Uint8Array>
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>
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
