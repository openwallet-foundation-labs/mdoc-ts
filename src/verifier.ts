import type { CoseKey } from '@owf/cose'
import { StatusListCwt } from '@owf/token-status-list'
import type { MdocContext } from './context.js'
import type { VerificationCallback } from './mdoc/check-callback.js'
import { type DeviceRequest, DeviceResponse, type SessionTranscript } from './mdoc/index.js'
import type { Document } from './mdoc/models/document.js'
import type { IdentifierListCwt } from './mdoc/models/identifier-list-cwt.js'

export class Verifier {
  public static async verifyDeviceResponse(
    options: {
      deviceRequest?: DeviceRequest
      deviceResponse: Uint8Array | DeviceResponse
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      trustedCertificates: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>
  ): Promise<Array<{ document: Document; trustedIssuanceChain: Uint8Array[]; statusList?: StatusListCwt; trustedStatusListChain?: Uint8Array[]; identifierList?: IdentifierListCwt; trustedIdentifierListChain?: Uint8Array[] }>> {
    const deviceResponse =
      options.deviceResponse instanceof DeviceResponse
        ? options.deviceResponse
        : DeviceResponse.decode(options.deviceResponse)

    return deviceResponse.verify(options, ctx)
  }
}
