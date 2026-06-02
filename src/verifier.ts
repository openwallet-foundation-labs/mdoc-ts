import type { CoseKey } from '@owf/cose'
import type { MdocContext } from './context.js'
import type { VerificationCallback } from './mdoc/check-callback.js'
import { type DeviceRequest, DeviceResponse, type SessionTranscript } from './mdoc/index.js'

export class Verifier {
  public static async verifyDeviceResponse(
    options: {
      deviceRequest?: DeviceRequest
      deviceResponse: Uint8Array | DeviceResponse
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates: Uint8Array[]
      trustedStatusCertificates?: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ) {
    const deviceResponse =
      options.deviceResponse instanceof DeviceResponse
        ? options.deviceResponse
        : DeviceResponse.decode(options.deviceResponse)

    await deviceResponse.verify(options, ctx)
  }
}
