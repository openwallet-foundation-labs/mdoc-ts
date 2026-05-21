import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { zUint8Array } from '../../utils/zod'

/**
 * StatusListInfo carries a reference to an IETF Token Status List
 * (draft-ietf-oauth-status-list) entry from inside the MSO's Status structure.
 *
 * Defined in ISO/IEC 18013-5 second edition (CD), 12.3.6.
 */
// NOTE: idx is `uint` in the spec (unbounded CBOR uint). We constrain to JS
// safe-integer range here, which is more than enough for real-world status
// list sizes (Number.MAX_SAFE_INTEGER is ~9 × 10^15).
const statusListInfoSchema = typedMap([
  ['uri', z.string()],
  ['idx', z.number().int().nonnegative()],
  ['certificate', zUint8Array.exactOptional()],
])

export type StatusListInfoDecodedStructure = z.output<typeof statusListInfoSchema>
export type StatusListInfoEncodedStructure = z.input<typeof statusListInfoSchema>

export type StatusListInfoOptions = {
  uri: string
  idx: number
  certificate?: Uint8Array
}

export class StatusListInfo extends CborStructure<StatusListInfoEncodedStructure, StatusListInfoDecodedStructure> {
  public static override get encodingSchema() {
    return statusListInfoSchema
  }

  public get uri() {
    return this.structure.get('uri')
  }

  public get idx() {
    return this.structure.get('idx')
  }

  public get certificate() {
    return this.structure.get('certificate')
  }

  public static create(options: StatusListInfoOptions): StatusListInfo {
    const map: StatusListInfoDecodedStructure = new TypedMap([
      ['uri', options.uri],
      ['idx', options.idx],
    ])
    if (options.certificate) {
      map.set('certificate', options.certificate)
    }
    return this.fromDecodedStructure(map)
  }
}
