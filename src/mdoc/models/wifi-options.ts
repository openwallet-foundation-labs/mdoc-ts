import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { typedMap } from '../../utils'
import { zUint8Array } from '../../utils/zod'

enum WifiOptionsKeys {
  Passphrase = 0,
  OperatingClass = 1,
  ChannelNumber = 2,
  SupportedBands = 3,
}

// WifiOptions uses integer keys per spec:
// WifiOptions = {
//   ? 0: tstr,  // Pass-phrase
//   ? 1: uint,  // Operating Class
//   ? 2: uint,  // Channel Number
//   ? 3: bstr   // Supported Bands
// }
const wifiOptionsSchema = typedMap([
  [WifiOptionsKeys.Passphrase, z.string().exactOptional()],
  [WifiOptionsKeys.OperatingClass, z.number().exactOptional()],
  [WifiOptionsKeys.ChannelNumber, z.number().exactOptional()],
  [WifiOptionsKeys.SupportedBands, zUint8Array.exactOptional()],
] as const)

export type WifiOptionsEncodedStructure = z.input<typeof wifiOptionsSchema>
export type WifiOptionsDecodedStructure = z.output<typeof wifiOptionsSchema>

export type WifiOptionsOptions = {
  passphrase?: string
  channelInfoOperatingClass?: number
  channelInfoChannelNumber?: number
  bandInfoSupportedBands?: Uint8Array
}

export class WifiOptions extends CborStructure<WifiOptionsEncodedStructure, WifiOptionsDecodedStructure> {
  public static override get encodingSchema() {
    return wifiOptionsSchema
  }

  public get encodedStructure() {
    return this.structure.toMap() as WifiOptionsEncodedStructure
  }

  public get passphrase() {
    return this.structure.get(WifiOptionsKeys.Passphrase)
  }

  public get channelInfoOperatingClass() {
    return this.structure.get(WifiOptionsKeys.OperatingClass)
  }

  public get channelInfoChannelNumber() {
    return this.structure.get(WifiOptionsKeys.ChannelNumber)
  }

  public get bandInfoSupportedBands() {
    return this.structure.get(WifiOptionsKeys.SupportedBands)
  }

  public static create(options: WifiOptionsOptions): WifiOptions {
    const entries: Array<[number, unknown]> = []

    if (options.passphrase !== undefined) {
      entries.push([WifiOptionsKeys.Passphrase, options.passphrase])
    }

    if (options.channelInfoOperatingClass !== undefined) {
      entries.push([WifiOptionsKeys.OperatingClass, options.channelInfoOperatingClass])
    }

    if (options.channelInfoChannelNumber !== undefined) {
      entries.push([WifiOptionsKeys.ChannelNumber, options.channelInfoChannelNumber])
    }

    if (options.bandInfoSupportedBands !== undefined) {
      entries.push([WifiOptionsKeys.SupportedBands, options.bandInfoSupportedBands])
    }

    const map = new Map(entries)
    return this.fromEncodedStructure(map)
  }
}
