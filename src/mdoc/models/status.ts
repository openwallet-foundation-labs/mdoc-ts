import { z } from 'zod'
import { CborStructure } from '../../cbor'
import { TypedMap, typedMap } from '../../utils'
import { IdentifierListInfo, type IdentifierListInfoEncodedStructure } from './identifier-list-info'
import { StatusListInfo, type StatusListInfoEncodedStructure } from './status-list-info'

/**
 * Status references one or both of the revocation mechanisms defined in
 * ISO/IEC 18013-5 second edition (CD), 12.3.6:
 *
 *   Status = {
 *     ? "status_list": StatusListInfo,       ; IETF Token Status List entry
 *     ? "identifier_list": IdentifierListInfo,
 *     * tstr => RFU,
 *   }
 *
 * Either or both members may be present. The mDL profile uses only the
 * VALID / INVALID states (no temporary suspension).
 *
 * Status is embedded inside the MobileSecurityObject as an optional member
 * so issuers can publish revocation status for issued credentials, and
 * verifiers can check it during presentation.
 */
const statusSchema = typedMap([
  ['status_list', z.instanceof(StatusListInfo).exactOptional()],
  ['identifier_list', z.instanceof(IdentifierListInfo).exactOptional()],
])

export type StatusDecodedStructure = z.output<typeof statusSchema>
export type StatusEncodedStructure = z.input<typeof statusSchema>

export type StatusOptions = {
  statusList?: StatusListInfo
  identifierList?: IdentifierListInfo
}

export class Status extends CborStructure<StatusEncodedStructure, StatusDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(statusSchema.in, statusSchema.out, {
      decode: (input) => {
        const map: StatusDecodedStructure = TypedMap.fromMap(input)

        if (input.has('status_list')) {
          map.set(
            'status_list',
            StatusListInfo.fromEncodedStructure(input.get('status_list') as StatusListInfoEncodedStructure)
          )
        }
        if (input.has('identifier_list')) {
          map.set(
            'identifier_list',
            IdentifierListInfo.fromEncodedStructure(
              input.get('identifier_list') as IdentifierListInfoEncodedStructure
            )
          )
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        const statusList = output.get('status_list')
        if (statusList) {
          map.set('status_list', statusList.encodedStructure)
        }
        const identifierList = output.get('identifier_list')
        if (identifierList) {
          map.set('identifier_list', identifierList.encodedStructure)
        }
        return map
      },
    })
  }

  public get statusList() {
    return this.structure.get('status_list')
  }

  public get identifierList() {
    return this.structure.get('identifier_list')
  }

  public static create(options: StatusOptions): Status {
    const map: StatusDecodedStructure = new TypedMap()
    if (options.statusList) {
      map.set('status_list', options.statusList)
    }
    if (options.identifierList) {
      map.set('identifier_list', options.identifierList)
    }
    return this.fromDecodedStructure(map)
  }
}
