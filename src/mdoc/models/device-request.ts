import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { DocRequest, type DocRequestEncodedStructure } from './doc-request'

const deviceRequestSchema = typedMap([
  ['version', z.string()],
  ['docRequests', z.array(z.instanceof(DocRequest))],
] as const)

export type DeviceRequestDecodedStructure = z.output<typeof deviceRequestSchema>
export type DeviceRequestEncodedStructure = z.input<typeof deviceRequestSchema>

export type DeviceRequestOptions = {
  version?: string
  docRequests: Array<DocRequest>
}

export class DeviceRequest extends CborStructure<DeviceRequestEncodedStructure, DeviceRequestDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceRequestSchema.in, deviceRequestSchema.out, {
      decode: (input) => {
        const map: DeviceRequestDecodedStructure = TypedMap.fromMap(input)
        const docRequests = input.get('docRequests') as unknown[]

        map.set(
          'docRequests',
          docRequests.map((dr) => DocRequest.fromEncodedStructure(dr as DocRequestEncodedStructure))
        )

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set(
          'docRequests',
          output.get('docRequests').map((dr) => dr.encodedStructure)
        )

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get docRequests() {
    return this.structure.get('docRequests')
  }

  public static create(options: DeviceRequestOptions): DeviceRequest {
    const map: DeviceRequestDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['docRequests', options.docRequests],
    ])
    return this.fromDecodedStructure(map)
  }
}
