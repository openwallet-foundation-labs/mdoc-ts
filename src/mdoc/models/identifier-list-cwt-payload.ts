import { CborStructure, RegisteredCwtClaimKey, TypedMap, typedMap } from '@owf/cose'
import z from 'zod'
import { IdentifierList, type IdentifierListEncodedStructure } from './identifier-list'

/**
 * CWT payload claim carrying the identifier list (ISO/IEC 18013-5 second
 * edition § 12.3.6). Mirrors `StatusListCwtPayload` from
 * `@owf/token-status-list`.
 */
export enum IdentifierListCwtClaimKey {
  IdentifierList = 65530,
}

/**
 * Generic CWT registered claim keys not yet exposed by `@owf/cose`'s
 * `RegisteredCwtClaimKey`. Inline pending an upstream addition.
 */
export enum CwtClaimKey {
  /** `typ` claim, RFC 9596 § 4.1. */
  Typ = 16,
}

/** CWT content type strings used by ISO 18013-5 revocation lists. */
export enum MediaTypes {
  IdentifierListCwt = 'application/identifierlist+cwt',
}

const identifierListCwtPayloadSchema = typedMap(
  [
    [RegisteredCwtClaimKey.Subject, z.string().exactOptional()],
    [RegisteredCwtClaimKey.IssuedAt, z.number().exactOptional()],
    // ISO 18013-5 § 12.3.6.3: "The exp claim shall be present."
    [RegisteredCwtClaimKey.ExpirationTime, z.number()],
    // § 12.3.6.4: "The value of the type claim shall be
    // 'application/identifierlist+cwt'".
    [CwtClaimKey.Typ, z.literal(MediaTypes.IdentifierListCwt)],
    [IdentifierListCwtClaimKey.IdentifierList, z.instanceof(IdentifierList)],
  ],
  { allowAdditionalKeys: true }
)

export type IdentifierListCwtPayloadEncodedStructure = z.infer<typeof identifierListCwtPayloadSchema>
export type IdentifierListCwtPayloadDecodedStructure = z.infer<typeof identifierListCwtPayloadSchema>

export type CreateIdentifierListCwtPayloadOptions = {
  identifierList: IdentifierList
  subject?: string
  issuedAt?: Date
  expirationTime?: Date
}

export class IdentifierListCwtPayload extends CborStructure<
  IdentifierListCwtPayloadEncodedStructure,
  IdentifierListCwtPayloadDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(identifierListCwtPayloadSchema.in, identifierListCwtPayloadSchema.out, {
      decode: (input) => {
        const map: IdentifierListCwtPayloadDecodedStructure = TypedMap.fromMap(input)
        map.set(
          IdentifierListCwtClaimKey.IdentifierList,
          IdentifierList.fromEncodedStructure(
            input.get(IdentifierListCwtClaimKey.IdentifierList) as IdentifierListEncodedStructure
          )
        )
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set(
          IdentifierListCwtClaimKey.IdentifierList,
          output.get(IdentifierListCwtClaimKey.IdentifierList).encodedStructure
        )
        return map
      },
    })
  }

  public static create(options: CreateIdentifierListCwtPayloadOptions) {
    if (!options.expirationTime) {
      // ISO 18013-5 § 12.3.6.3: exp claim shall be present.
      throw new Error('IdentifierListCwtPayload.create: expirationTime is required')
    }
    const map: IdentifierListCwtPayloadDecodedStructure = new TypedMap([
      [RegisteredCwtClaimKey.ExpirationTime, Math.floor(options.expirationTime.getTime() / 1000)],
      [CwtClaimKey.Typ, MediaTypes.IdentifierListCwt],
      [IdentifierListCwtClaimKey.IdentifierList, options.identifierList],
    ])
    if (options.subject !== undefined) {
      map.set(RegisteredCwtClaimKey.Subject, options.subject)
    }
    map.set(RegisteredCwtClaimKey.IssuedAt, Math.floor((options.issuedAt ?? new Date()).getTime() / 1000))
    return new IdentifierListCwtPayload(identifierListCwtPayloadSchema.parse(map.toMap()))
  }

  public get identifierList() {
    return this.structure.get(IdentifierListCwtClaimKey.IdentifierList)
  }

  public get subject() {
    return this.structure.get(RegisteredCwtClaimKey.Subject)
  }

  public get issuedAt() {
    const v = this.structure.get(RegisteredCwtClaimKey.IssuedAt)
    return v !== undefined ? new Date(v * 1000) : undefined
  }

  public get expirationTime() {
    const v = this.structure.get(RegisteredCwtClaimKey.ExpirationTime)
    return v !== undefined ? new Date(v * 1000) : undefined
  }
}
