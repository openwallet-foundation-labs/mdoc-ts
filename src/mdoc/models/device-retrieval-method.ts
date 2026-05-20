import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { BleOptions, type BleOptionsEncodedStructure } from './ble-options'
import { NfcOptions, type NfcOptionsEncodedStructure } from './nfc-options'
import type { RetrievalOptions } from './retrieval-options'
import { WifiOptions, type WifiOptionsEncodedStructure } from './wifi-options'

export enum DeviceRetrievalMethodType {
  Nfc = 1,
  Ble = 2,
  WifiAware = 3,
}

const deviceRetrievalMethodEncodedSchema = z.tuple([
  z.enum(DeviceRetrievalMethodType).or(z.number()),
  z.number(),
  z.map(z.unknown(), z.unknown()),
])

const deviceRetrievalMethodDecodedSchema = z.object({
  // Parsing should not fail if one unknown device retrieval method is included
  type: z.enum(DeviceRetrievalMethodType).or(z.number()),
  version: z.number(),
  retrievalOptions: z.union([
    z.instanceof(NfcOptions),
    z.instanceof(BleOptions),
    z.instanceof(WifiOptions),
    // Parsing should not fail if one unknown device retrieval method is included
    z.map(z.unknown(), z.unknown()),
  ]),
})

export type DeviceRetrievalMethodEncodedStructure = z.infer<typeof deviceRetrievalMethodEncodedSchema>
export type DeviceRetrievalMethodDecodedStructure = z.infer<typeof deviceRetrievalMethodDecodedSchema>

export type DeviceRetrievalMethodOptions = {
  type: DeviceRetrievalMethodType | number
  version: number
  retrievalOptions: RetrievalOptions
}

export class DeviceRetrievalMethod extends CborStructure<
  DeviceRetrievalMethodEncodedStructure,
  DeviceRetrievalMethodDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(deviceRetrievalMethodEncodedSchema, deviceRetrievalMethodDecodedSchema, {
      decode: ([type, version, retrievalOptions]) => {
        let options: RetrievalOptions | Map<unknown, unknown>

        if (type === DeviceRetrievalMethodType.Nfc) {
          options = NfcOptions.fromEncodedStructure(retrievalOptions as NfcOptionsEncodedStructure)
        } else if (type === DeviceRetrievalMethodType.Ble) {
          options = BleOptions.fromEncodedStructure(retrievalOptions as BleOptionsEncodedStructure)
        } else if (type === DeviceRetrievalMethodType.WifiAware) {
          options = WifiOptions.fromEncodedStructure(retrievalOptions as WifiOptionsEncodedStructure)
        } else {
          // Unknown type
          options = retrievalOptions
        }

        return {
          type,
          version,
          retrievalOptions: options,
        }
      },
      encode: ({ type, version, retrievalOptions }) =>
        [
          type,
          version,
          retrievalOptions instanceof CborStructure ? retrievalOptions.encodedStructure : retrievalOptions,
        ] satisfies DeviceRetrievalMethodEncodedStructure,
    })
  }

  public get type() {
    return this.structure.type
  }

  public get version() {
    return this.structure.version
  }

  public get retrievalOptions() {
    return this.structure.retrievalOptions
  }

  public static create(options: DeviceRetrievalMethodOptions): DeviceRetrievalMethod {
    return this.fromDecodedStructure({
      type: options.type,
      version: options.version,
      retrievalOptions: options.retrievalOptions,
    })
  }
}
