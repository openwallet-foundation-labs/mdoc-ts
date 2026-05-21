import type { DigestAlgorithm } from '@owf/cose'
import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { DeviceKeyInfo, type DeviceKeyInfoEncodedStructure } from './device-key-info'
import type { DocType } from './doctype'
import { Status, type StatusEncodedStructure } from './status'
import { ValidityInfo, type ValidityInfoEncodedStructure } from './validity-info'
import { ValueDigests, type ValueDigestsStructure } from './value-digests'

// Zod schema for MobileSecurityObject
// MSO has string keys, so we use z.object and set mapsAsObjects: true
const mobileSecurityObjectSchema = typedMap([
  // mDOC only defines 1.0
  ['version', z.literal('1.0')],
  ['digestAlgorithm', z.enum(['SHA-256', 'SHA-384', 'SHA-512'])],
  ['docType', z.string()],
  ['valueDigests', z.instanceof(ValueDigests)],
  ['deviceKeyInfo', z.instanceof(DeviceKeyInfo)],
  ['validityInfo', z.instanceof(ValidityInfo)],
  // Optional Status, defined in ISO/IEC 18013-5 second edition (CD), 12.3.6.
  // Carries Status List and/or Identifier List references for revocation.
  ['status', z.instanceof(Status).exactOptional()],
])

export type MobileSecurityObjectDecodedStructure = z.output<typeof mobileSecurityObjectSchema>
export type MobileSecurityObjectEncodedStructure = z.input<typeof mobileSecurityObjectSchema>

export type MobileSecurityObjectOptions = {
  version?: '1.0'
  digestAlgorithm: DigestAlgorithm
  docType: DocType
  valueDigests: ValueDigests
  validityInfo: ValidityInfo
  deviceKeyInfo: DeviceKeyInfo
  status?: Status
}

export class MobileSecurityObject extends CborStructure<
  MobileSecurityObjectEncodedStructure,
  MobileSecurityObjectDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(mobileSecurityObjectSchema.in, mobileSecurityObjectSchema.out, {
      decode: (input) => {
        const map: MobileSecurityObjectDecodedStructure = TypedMap.fromMap(input)

        // Need to transform into class types
        map.set('valueDigests', ValueDigests.fromEncodedStructure(input.get('valueDigests') as ValueDigestsStructure))
        map.set(
          'deviceKeyInfo',
          DeviceKeyInfo.fromEncodedStructure(input.get('deviceKeyInfo') as DeviceKeyInfoEncodedStructure)
        )
        map.set(
          'validityInfo',
          ValidityInfo.fromEncodedStructure(input.get('validityInfo') as ValidityInfoEncodedStructure)
        )

        if (input.has('status')) {
          map.set('status', Status.fromEncodedStructure(input.get('status') as StatusEncodedStructure))
        }

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>

        // Need to transform into class encoded structure types
        map.set('valueDigests', output.get('valueDigests').encodedStructure)
        map.set('deviceKeyInfo', output.get('deviceKeyInfo').encodedStructure)
        map.set('validityInfo', output.get('validityInfo').encodedStructure)

        const status = output.get('status')
        if (status) {
          map.set('status', status.encodedStructure)
        }

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get digestAlgorithm() {
    return this.structure.get('digestAlgorithm')
  }

  public get docType() {
    return this.structure.get('docType')
  }

  public get validityInfo() {
    return this.structure.get('validityInfo')
  }

  public get valueDigests() {
    return this.structure.get('valueDigests')
  }

  public get deviceKeyInfo() {
    return this.structure.get('deviceKeyInfo')
  }

  public get status() {
    return this.structure.get('status')
  }

  public static create(options: MobileSecurityObjectOptions): MobileSecurityObject {
    // Property order MUST match spec: version, digestAlgorithm, valueDigests, deviceKeyInfo, docType, validityInfo
    const map: MobileSecurityObjectDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['digestAlgorithm', options.digestAlgorithm],
      ['valueDigests', options.valueDigests],
      ['deviceKeyInfo', options.deviceKeyInfo],
      ['docType', options.docType],
      ['validityInfo', options.validityInfo],
    ])

    if (options.status) {
      map.set('status', options.status)
    }

    return this.fromDecodedStructure(map)
  }
}
