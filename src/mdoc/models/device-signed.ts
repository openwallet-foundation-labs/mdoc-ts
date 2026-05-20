import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { DeviceAuth, type DeviceAuthEncodedStructure } from './device-auth'
import { DeviceNamespaces, type DeviceNamespacesEncodedStructure } from './device-namespaces'

const deviceSignedSchema = typedMap([
  ['nameSpaces', z.instanceof(DeviceNamespaces)],
  ['deviceAuth', z.instanceof(DeviceAuth)],
] as const)

export type DeviceSignedDecodedStructure = z.output<typeof deviceSignedSchema>
export type DeviceSignedEncodedStructure = z.input<typeof deviceSignedSchema>

export type DeviceSignedOptions = {
  deviceNamespaces: DeviceNamespaces
  deviceAuth: DeviceAuth
}

export class DeviceSigned extends CborStructure<DeviceSignedEncodedStructure, DeviceSignedDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceSignedSchema.in, deviceSignedSchema.out, {
      decode: (input) => {
        const map: DeviceSignedDecodedStructure = TypedMap.fromMap(input)

        const nameSpaces = input.get('nameSpaces') as DataItem
        map.set(
          'nameSpaces',
          DeviceNamespaces.fromEncodedStructure(nameSpaces.data as DeviceNamespacesEncodedStructure)
        )
        map.set('deviceAuth', DeviceAuth.fromEncodedStructure(input.get('deviceAuth') as DeviceAuthEncodedStructure))

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('nameSpaces', DataItem.fromData(output.get('nameSpaces').encodedStructure))
        map.set('deviceAuth', output.get('deviceAuth').encodedStructure)

        return map
      },
    })
  }

  public get deviceNamespaces() {
    return this.structure.get('nameSpaces')
  }

  public get deviceAuth() {
    return this.structure.get('deviceAuth')
  }

  public static create(options: DeviceSignedOptions): DeviceSigned {
    const map: DeviceSignedDecodedStructure = new TypedMap([
      ['nameSpaces', options.deviceNamespaces],
      ['deviceAuth', options.deviceAuth],
    ])
    return this.fromDecodedStructure(map)
  }
}
