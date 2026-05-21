import { CborStructure, DataItem, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { stringToBytes } from '@owf/identity-common'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import type { EDeviceKey } from './e-device-key'
import { EReaderKey } from './e-reader-key'
import type { SessionTranscript } from './session-transcript'

const sessionEstablishmentSchema = typedMap([
  ['eReaderKey', z.instanceof(EReaderKey)],
  ['data', zUint8Array],
] as const)

export type SessionEstablishmentDecodedStructure = z.output<typeof sessionEstablishmentSchema>
export type SessionEstablishmentEncodedStructure = z.input<typeof sessionEstablishmentSchema>

export type SessionEstablishmentOptions = {
  eReaderKey: EReaderKey
  data: Uint8Array
}

export class SessionEstablishment extends CborStructure<
  SessionEstablishmentEncodedStructure,
  SessionEstablishmentDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(sessionEstablishmentSchema.in, sessionEstablishmentSchema.out, {
      decode: (input) => {
        const map: SessionEstablishmentDecodedStructure = TypedMap.fromMap(input)

        const eReaderKeyDataItem = input.get('eReaderKey')
        map.set('eReaderKey', EReaderKey.fromDataItem(eReaderKeyDataItem))

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('eReaderKey', DataItem.fromData(output.get('eReaderKey').encodedStructure))

        return map
      },
    })
  }

  public get eReaderKey() {
    return this.structure.get('eReaderKey')
  }

  public get data() {
    return this.structure.get('data')
  }

  public async decryptedData(
    options: {
      eDeviceKeyPrivate: EDeviceKey
      eReaderKeyPublic: EReaderKey
      sessionTranscript: SessionTranscript
    },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const _key = await ctx.crypto.hdkf({
      digestAlgorithm: 'SHA-256',
      privateKey: options.eDeviceKeyPrivate.privateKey,
      publicKey: options.eReaderKeyPublic.publicKey,
      salt: options.sessionTranscript.encode({ asDataItem: true }),
      info: stringToBytes('SKReader'),
    })

    // TODO: we need to add a ctx.crypto.decrypt method
    throw new Error('unimplemented: ctx.crypto.decrypt must be added')
  }

  public static create(options: SessionEstablishmentOptions): SessionEstablishment {
    const map: SessionEstablishmentDecodedStructure = new TypedMap([
      ['eReaderKey', options.eReaderKey],
      ['data', options.data],
    ])

    return this.fromDecodedStructure(map)
  }
}
