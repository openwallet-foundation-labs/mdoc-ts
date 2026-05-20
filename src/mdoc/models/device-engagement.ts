import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { DeviceRetrievalMethod, type DeviceRetrievalMethodEncodedStructure } from './device-retrieval-method'
import { ProtocolInfo, type ProtocolInfoStructure } from './protocol-info'
import { Security, type SecurityEncodedStructure } from './security'
import { ServerRetrievalMethod, type ServerRetrievalMethodEncodedStructure } from './server-retrieval-method'

enum DeviceEngagementKeys {
  Version = 0,
  Security = 1,
  DeviceRetrievalMethods = 2,
  ServerRetrievalMethods = 3,
  ProtocolInfo = 4,
}

const deviceEngagementSchema = typedMap([
  [DeviceEngagementKeys.Version, z.string()],
  [DeviceEngagementKeys.Security, z.instanceof(Security)],
  [DeviceEngagementKeys.DeviceRetrievalMethods, z.array(z.instanceof(DeviceRetrievalMethod)).exactOptional()],
  [DeviceEngagementKeys.ServerRetrievalMethods, z.array(z.instanceof(ServerRetrievalMethod)).exactOptional()],
  [DeviceEngagementKeys.ProtocolInfo, z.instanceof(ProtocolInfo).exactOptional()],
] as const)

export type DeviceEngagementEncodedStructure = z.input<typeof deviceEngagementSchema>
export type DeviceEngagementDecodedStructure = z.output<typeof deviceEngagementSchema>

export type DeviceEngagementOptions = {
  version: string
  security: Security
  deviceRetrievalMethods?: Array<DeviceRetrievalMethod>
  serverRetrievalMethods?: Array<ServerRetrievalMethod>
  protocolInfo?: ProtocolInfo
}

export class DeviceEngagement extends CborStructure<
  DeviceEngagementEncodedStructure,
  DeviceEngagementDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(deviceEngagementSchema.in, deviceEngagementSchema.out, {
      decode: (input) => {
        const map: DeviceEngagementDecodedStructure = TypedMap.fromMap(input)

        map.set(
          DeviceEngagementKeys.Security,
          Security.fromEncodedStructure(input.get(DeviceEngagementKeys.Security) as SecurityEncodedStructure)
        )

        if (input.has(DeviceEngagementKeys.DeviceRetrievalMethods)) {
          const deviceMethods = input.get(
            DeviceEngagementKeys.DeviceRetrievalMethods
          ) as DeviceRetrievalMethodEncodedStructure[]
          map.set(
            DeviceEngagementKeys.DeviceRetrievalMethods,
            deviceMethods.map((encoded) => DeviceRetrievalMethod.fromEncodedStructure(encoded))
          )
        }

        if (input.has(DeviceEngagementKeys.ServerRetrievalMethods)) {
          const serverMethods = input.get(
            DeviceEngagementKeys.ServerRetrievalMethods
          ) as ServerRetrievalMethodEncodedStructure[]
          map.set(
            DeviceEngagementKeys.ServerRetrievalMethods,
            serverMethods.map((encoded) => ServerRetrievalMethod.fromEncodedStructure(encoded))
          )
        }

        if (input.has(DeviceEngagementKeys.ProtocolInfo)) {
          map.set(
            DeviceEngagementKeys.ProtocolInfo,
            ProtocolInfo.fromEncodedStructure(input.get(DeviceEngagementKeys.ProtocolInfo) as ProtocolInfoStructure)
          )
        }

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>

        map.set(DeviceEngagementKeys.Security, output.get(DeviceEngagementKeys.Security).encodedStructure)

        const deviceRetrievalMethods = output.get(DeviceEngagementKeys.DeviceRetrievalMethods)
        if (deviceRetrievalMethods) {
          map.set(
            DeviceEngagementKeys.DeviceRetrievalMethods,
            deviceRetrievalMethods.map((drm) => drm.encodedStructure)
          )
        }

        const serverRetrievalMethods = output.get(DeviceEngagementKeys.ServerRetrievalMethods)
        if (serverRetrievalMethods) {
          map.set(
            DeviceEngagementKeys.ServerRetrievalMethods,
            serverRetrievalMethods.map((srm) => srm.encodedStructure)
          )
        }

        const protocolInfo = output.get(DeviceEngagementKeys.ProtocolInfo)
        if (protocolInfo) {
          map.set(DeviceEngagementKeys.ProtocolInfo, protocolInfo.encodedStructure)
        }

        return map
      },
    })
  }

  public get version() {
    return this.structure.get(DeviceEngagementKeys.Version)
  }

  public get security() {
    return this.structure.get(DeviceEngagementKeys.Security)
  }

  public get deviceRetrievalMethods() {
    return this.structure.get(DeviceEngagementKeys.DeviceRetrievalMethods)
  }

  public get serverRetrievalMethods() {
    return this.structure.get(DeviceEngagementKeys.ServerRetrievalMethods)
  }

  public get protocolInfo() {
    return this.structure.get(DeviceEngagementKeys.ProtocolInfo)
  }

  public static create(options: DeviceEngagementOptions): DeviceEngagement {
    const map = new Map<number, unknown>([
      [DeviceEngagementKeys.Version, options.version],
      [DeviceEngagementKeys.Security, options.security],
    ])

    if (options.deviceRetrievalMethods !== undefined) {
      map.set(DeviceEngagementKeys.DeviceRetrievalMethods, options.deviceRetrievalMethods)
    }

    if (options.serverRetrievalMethods !== undefined) {
      map.set(DeviceEngagementKeys.ServerRetrievalMethods, options.serverRetrievalMethods)
    }

    if (options.protocolInfo !== undefined) {
      map.set(DeviceEngagementKeys.ProtocolInfo, options.protocolInfo)
    }

    return this.fromEncodedStructure(map)
  }
}
