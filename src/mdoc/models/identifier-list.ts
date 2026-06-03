import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { compareBytes } from '@owf/identity-common'
import { z } from 'zod'

/**
 * IdentifierList payload structure carried inside an `IdentifierListCwt`.
 * ISO/IEC 18013-5 second edition § 12.3.6.4:
 *
 *   IdentifierList = {
 *     "identifiers"      : { * Identifier => IdentifierInfo },
 *     ? "aggregation_uri": Aggregation_uri,
 *     * tstr             => RFU
 *   }
 *
 *   IdentifierInfo = { tstr/int => RFU }   ; empty-allowed RFU map
 *   Identifier     = bstr
 *
 * Presence of an `Identifier` in `identifiers` means the MSO carrying that
 * id in its `identifier_list` element is revoked; absence means valid.
 */
const identifierInfoSchema = z.map(z.union([z.string(), z.number()]), z.unknown())

const identifierListSchema = typedMap(
  [
    ['identifiers', z.map(zUint8Array, identifierInfoSchema)],
    ['aggregation_uri', z.string().exactOptional()],
  ],
  { allowAdditionalKeys: true }
)

export type IdentifierListDecodedStructure = z.output<typeof identifierListSchema>
export type IdentifierListEncodedStructure = z.input<typeof identifierListSchema>

export type IdentifierListOptions = {
  identifiers: Array<Uint8Array>
  aggregationUri?: string
}

export class IdentifierList extends CborStructure<IdentifierListEncodedStructure, IdentifierListDecodedStructure> {
  public static override get encodingSchema() {
    return identifierListSchema
  }

  public get identifiers() {
    return this.structure.get('identifiers')
  }

  public get aggregationUri() {
    return this.structure.get('aggregation_uri')
  }

  public includes(id: Uint8Array): boolean {
    const ids = this.identifiers
    if (!ids) return false
    for (const entry of ids.keys()) {
      if (compareBytes(entry, id)) return true
    }
    return false
  }

  public static create(options: IdentifierListOptions): IdentifierList {
    const ids = new Map<Uint8Array, Map<string | number, unknown>>()
    for (const id of options.identifiers) ids.set(id, new Map())
    const map: IdentifierListDecodedStructure = new TypedMap([['identifiers', ids]])
    if (options.aggregationUri !== undefined) {
      map.set('aggregation_uri', options.aggregationUri)
    }
    return this.fromDecodedStructure(map)
  }
}
