import { CborStructure, TypedMap, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'

/**
 * IdentifierListInfo carries an opaque per-MSO identifier and the location of
 * the published list of revoked identifiers.
 *
 * Defined in ISO/IEC 18013-5 second edition (CD), 12.3.6.
 *
 * The `id` is an opaque byte string the issuer assigns to this MSO (recommended
 * unique and random per credential). Revocation is signalled by publishing the
 * id in the identifier list at `uri`. Absence from the list means the credential
 * is valid.
 */
const identifierListInfoSchema = typedMap([
  ['id', zUint8Array],
  ['uri', z.string()],
  ['certificate', zUint8Array.exactOptional()],
])

export type IdentifierListInfoDecodedStructure = z.output<typeof identifierListInfoSchema>
export type IdentifierListInfoEncodedStructure = z.input<typeof identifierListInfoSchema>

export type IdentifierListInfoOptions = {
  id: Uint8Array
  uri: string
  certificate?: Uint8Array
}

export class IdentifierListInfo extends CborStructure<
  IdentifierListInfoEncodedStructure,
  IdentifierListInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return identifierListInfoSchema
  }

  public get id() {
    return this.structure.get('id')
  }

  public get uri() {
    return this.structure.get('uri')
  }

  public get certificate() {
    return this.structure.get('certificate')
  }

  public static create(options: IdentifierListInfoOptions): IdentifierListInfo {
    const map: IdentifierListInfoDecodedStructure = new TypedMap([
      ['id', options.id],
      ['uri', options.uri],
    ])
    if (options.certificate) {
      map.set('certificate', options.certificate)
    }
    return this.fromDecodedStructure(map)
  }
}
