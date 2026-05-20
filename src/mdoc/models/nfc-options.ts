import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { typedMap } from '../../utils'

enum NfcOptionsKeys {
  MaxCommandDataLength = 0,
  MaxResponseDataLength = 1,
}

// NfcOptions uses integer keys per spec:
// NfcOptions = {
//   0 : uint, // Max command data length
//   1 : uint  // Max response data length
// }
const nfcOptionsSchema = typedMap([
  [NfcOptionsKeys.MaxCommandDataLength, z.number()],
  [NfcOptionsKeys.MaxResponseDataLength, z.number()],
] as const)

export type NfcOptionsEncodedStructure = z.input<typeof nfcOptionsSchema>
export type NfcOptionsDecodedStructure = z.output<typeof nfcOptionsSchema>

export type NfcOptionsOptions = {
  maxCommandDataLength: number
  maxResponseDataLength: number
}

export class NfcOptions extends CborStructure<NfcOptionsEncodedStructure, NfcOptionsDecodedStructure> {
  public static override get encodingSchema() {
    return nfcOptionsSchema
  }

  public get maxCommandDataLength() {
    return this.structure.get(NfcOptionsKeys.MaxCommandDataLength)
  }

  public get maxResponseDataLength() {
    return this.structure.get(NfcOptionsKeys.MaxResponseDataLength)
  }

  public static create(options: NfcOptionsOptions): NfcOptions {
    const map = new Map([
      [NfcOptionsKeys.MaxCommandDataLength, options.maxCommandDataLength],
      [NfcOptionsKeys.MaxResponseDataLength, options.maxResponseDataLength],
    ])

    return this.fromEncodedStructure(map)
  }
}
