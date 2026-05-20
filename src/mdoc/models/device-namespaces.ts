import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { DeviceSignedItems, type DeviceSignedItemsStructure, deviceSignedItemsSchema } from './device-signed-items'
import type { Namespace } from './namespace'

const deviceNamespacesEncodedSchema = z.map(z.string(), deviceSignedItemsSchema)
const deviceNamespacesDecodedSchema = z.map(z.string(), z.instanceof(DeviceSignedItems))

export type DeviceNamespacesDecodedStructure = z.infer<typeof deviceNamespacesDecodedSchema>
export type DeviceNamespacesEncodedStructure = z.infer<typeof deviceNamespacesEncodedSchema>

export type DeviceNamespacesOptions = {
  deviceNamespaces: Map<Namespace, DeviceSignedItems>
}

export class DeviceNamespaces extends CborStructure<
  DeviceNamespacesEncodedStructure,
  DeviceNamespacesDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(deviceNamespacesEncodedSchema, deviceNamespacesDecodedSchema, {
      decode: (input) => {
        const deviceNamespaces = new Map<Namespace, DeviceSignedItems>()
        input.forEach((value, key) => {
          deviceNamespaces.set(key, DeviceSignedItems.fromEncodedStructure(value as DeviceSignedItemsStructure))
        })
        return deviceNamespaces
      },
      encode: (output) => {
        const map = new Map()
        output.forEach((value, key) => {
          map.set(key, value.encodedStructure)
        })
        return map
      },
    })
  }

  public get deviceNamespaces() {
    return this.structure
  }

  public static create(options: DeviceNamespacesOptions): DeviceNamespaces {
    return this.fromDecodedStructure(options.deviceNamespaces)
  }
}
