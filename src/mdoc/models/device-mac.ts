import type { CoseKey, Mac0Options } from '@owf/cose'
import { Mac0, type Mac0DecodedStructure, type Mac0EncodedStructure } from '@owf/cose'
import type { MdocContext } from '../../context'
import { stringToBytes } from '../../utils'
import { SessionTranscript } from './session-transcript'

export type DeviceMacEncodedStructure = Mac0EncodedStructure
export type DeviceMacDecodedStructure = Mac0DecodedStructure
export type DeviceMacOptions = Mac0Options

export class DeviceMac extends Mac0 {
  public async verify(
    options: {
      publicKey: CoseKey
      privateKey: CoseKey
      info?: 'EMacKey' | 'SKReader' | 'SKDevice'
      sessionTranscript: SessionTranscript | Uint8Array
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const key = await this.createDeviceMacKey(options, ctx)

    return ctx.cose.mac0.verify({
      mac0: this,
      key,
    })
  }

  public static create(options: DeviceMacOptions) {
    return super.create(options) as DeviceMac
  }

  public async createDeviceMacKey(
    options: {
      publicKey: CoseKey
      privateKey: CoseKey
      sessionTranscript: SessionTranscript | Uint8Array
      info?: 'EMacKey' | 'SKReader' | 'SKDevice'
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    return await ctx.crypto.hdkf({
      privateKey: options.privateKey.privateKey,
      publicKey: options.publicKey.publicKey,
      salt: await ctx.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes:
          options.sessionTranscript instanceof SessionTranscript
            ? options.sessionTranscript.encode({ asDataItem: true })
            : options.sessionTranscript,
      }),
      info: stringToBytes(options.info ?? 'EMacKey'),
    })
  }
}
