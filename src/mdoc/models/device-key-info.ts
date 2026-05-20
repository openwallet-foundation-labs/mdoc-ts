import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { DeviceKey, type DeviceKeyEncodedStructure } from './device-key'
import { KeyAuthorizations, type KeyAuthorizationsEncodedStructure } from './key-authorizations'
import { KeyInfo, type KeyInfoEncodedStructure } from './key-info'

const deviceKeyInfoSchema = typedMap([
  ['deviceKey', z.instanceof(DeviceKey)],
  ['keyAuthorizations', z.instanceof(KeyAuthorizations).exactOptional()],
  ['keyInfo', z.instanceof(KeyInfo).exactOptional()],
] as const)

export type DeviceKeyInfoDecodedStructure = z.output<typeof deviceKeyInfoSchema>
export type DeviceKeyInfoEncodedStructure = z.input<typeof deviceKeyInfoSchema>

export type DeviceKeyInfoOptions = {
  deviceKey: DeviceKey
  keyAuthorizations?: KeyAuthorizations
  keyInfo?: KeyInfo
}

export class DeviceKeyInfo extends CborStructure<DeviceKeyInfoEncodedStructure, DeviceKeyInfoDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceKeyInfoSchema.in, deviceKeyInfoSchema.out, {
      decode: (input) => {
        const map: DeviceKeyInfoDecodedStructure = TypedMap.fromMap(input)

        map.set('deviceKey', DeviceKey.fromEncodedStructure(input.get('deviceKey') as DeviceKeyEncodedStructure))

        if (input.has('keyAuthorizations')) {
          map.set(
            'keyAuthorizations',
            KeyAuthorizations.fromEncodedStructure(input.get('keyAuthorizations') as KeyAuthorizationsEncodedStructure)
          )
        }
        if (input.has('keyInfo')) {
          map.set('keyInfo', KeyInfo.fromEncodedStructure(input.get('keyInfo') as KeyInfoEncodedStructure))
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('deviceKey', output.get('deviceKey').encodedStructure)

        const keyAuthorizations = output.get('keyAuthorizations')
        if (keyAuthorizations) {
          map.set('keyAuthorizations', keyAuthorizations.encodedStructure)
        }
        const keyInfo = output.get('keyInfo')
        if (keyInfo) {
          map.set('keyInfo', keyInfo.encodedStructure)
        }
        return map
      },
    })
  }

  public get deviceKey() {
    return this.structure.get('deviceKey')
  }

  public get keyAuthorizations() {
    return this.structure.get('keyAuthorizations')
  }

  public get keyInfo() {
    return this.structure.get('keyInfo')
  }

  public static create(options: DeviceKeyInfoOptions): DeviceKeyInfo {
    const map: DeviceKeyInfoDecodedStructure = new TypedMap([['deviceKey', options.deviceKey]])
    if (options.keyAuthorizations) {
      map.set('keyAuthorizations', options.keyAuthorizations)
    }
    if (options.keyInfo) {
      map.set('keyInfo', options.keyInfo)
    }
    return this.fromDecodedStructure(map)
  }
}
