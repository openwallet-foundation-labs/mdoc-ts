import {
  type CreateCwtPayloadOptions,
  CwtClaimVerificationError,
  CwtPayload,
  cwtPayloadClaimsFromOptions,
  extendCwtPayloadClaims,
  RegisteredCwtClaimKey,
  TypedMap,
  type VerifyCwtClaimsOptions,
} from '@owf/cose'
import { StatusListCwtClaimKey } from '@owf/token-status-list'
import z from 'zod'
import { InvalidRevocationListError } from '../errors'
import { IdentifierList, type IdentifierListEncodedStructure } from './identifier-list'

/**
 * CWT payload claim carrying the identifier list (ISO/IEC 18013-5 second edition § 12.3.6.4).
 * Mirrors `StatusListCwtClaimKey` from `@owf/token-status-list`.
 */
export enum IdentifierListCwtClaimKey {
  IdentifierList = 65530,
}

/**
 * The registered CWT claims, with the ones an identifier list CWT requires narrowed to
 * non-optional, plus the identifier list claim itself.
 */
const identifierListCwtPayloadSchema = extendCwtPayloadClaims(
  [
    // § 12.3.6.3 defers to the Token Status List specification, where `sub` and `iat` are
    // REQUIRED claims of a Status List Token. `sub` shall equal the `uri` of the
    // `IdentifierListInfo` that pointed here; that equality is checked by `verifyClaims`.
    [RegisteredCwtClaimKey.Subject, z.string()],
    [RegisteredCwtClaimKey.IssuedAt, z.number()],
    // § 12.3.6.3: "The exp claim shall be present."
    [RegisteredCwtClaimKey.ExpirationTime, z.number()],
    [IdentifierListCwtClaimKey.IdentifierList, z.instanceof(IdentifierList)],
    // § 12.3.6.4: "The StatusList claim shall not be present in the CWT claims set." Declared as
    // `never` rather than checked afterwards, so the two revocation mechanisms cannot be mixed in
    // one token and the claims set is rejected where every other claim is validated.
    [
      StatusListCwtClaimKey.StatusList,
      z
        .never({
          error: `The StatusList claim (${StatusListCwtClaimKey.StatusList}) shall not be present in an identifier list CWT (ISO 18013-5 § 12.3.6.4)`,
        })
        .exactOptional(),
    ],
  ] as const,
  { keyLabels: { ...IdentifierListCwtClaimKey, ...StatusListCwtClaimKey } }
)

export type IdentifierListCwtPayloadEncodedStructure = z.input<typeof identifierListCwtPayloadSchema>
export type IdentifierListCwtPayloadDecodedStructure = z.infer<typeof identifierListCwtPayloadSchema>

export type CreateIdentifierListCwtPayloadOptions = Omit<CreateCwtPayloadOptions, 'subject' | 'expirationTime'> & {
  identifierList: IdentifierList

  /**
   * URI the list is published at. Becomes the `sub` claim, and shall equal the `uri` of the MSO's
   * `IdentifierListInfo`.
   */
  uri: string

  /** § 12.3.6.3: "The exp claim shall be present." */
  expirationTime: Date
}

/**
 * The options {@link IdentifierListCwtPayload.verifyClaims} takes: the generic CWT ones, with `sub`
 * replaced by the `uri` it has to be equal to. Matches `VerifyStatusListCwtClaimsOptions`, so both
 * revocation mechanisms are verified through the same shape.
 */
export type VerifyIdentifierListCwtClaimsOptions = Omit<VerifyCwtClaimsOptions, 'expectedSubject' | 'keyLabels'> & {
  /** The `uri` of the `IdentifierListInfo` the token was fetched for, which `sub` must equal. */
  uri: string
}

/**
 * The claims set of an identifier list CWT (ISO/IEC 18013-5 second edition § 12.3.6.4).
 *
 * The registered claims — `sub`, `iat`, `exp` — come from {@link CwtPayload}, and narrow to
 * non-optional here because the schema above redeclares them as required.
 */
export class IdentifierListCwtPayload extends CwtPayload<IdentifierListCwtPayloadDecodedStructure> {
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

  public static override create(options: CreateIdentifierListCwtPayloadOptions) {
    // `iat` is required for a status list token, so it defaults to now rather than being omitted.
    // NOTE: applied after the spread, so that an explicit `issuedAt: undefined` — what passing
    // through an optional value gives — defaults the same way omitting the key does.
    const claims = cwtPayloadClaimsFromOptions({
      ...options,
      subject: options.uri,
      issuedAt: options.issuedAt ?? new Date(),
    })

    claims.set(IdentifierListCwtClaimKey.IdentifierList, options.identifierList)

    return this.fromDecodedStructure(TypedMap.fromMap(claims))
  }

  /** `identifier_list` (65530) */
  public get identifierList(): IdentifierList {
    return this.getClaim(IdentifierListCwtClaimKey.IdentifierList)
  }

  /**
   * Verifies the claims of an identifier list token, on top of the generic CWT ones. § 12.3.6.1
   * makes the Token Status List verification requirements binding on both revocation mechanisms,
   * so `sub` and `iat` are REQUIRED and `sub` has to match the URI the token was referenced by —
   * without that check a list published for one URI can be replayed for another under the same
   * trust anchor. § 12.3.6.3 additionally requires `exp`.
   *
   * The counterpart of `StatusListCwtPayload.verifyClaims`, with the same defaults, including a
   * 30 second clock skew tolerance.
   *
   * @throws InvalidRevocationListError if a required claim is missing, `sub` is not the referenced
   *   URI, or the token is outside its validity window.
   */
  public override verifyClaims({ uri, requiredClaims = [], ...options }: VerifyIdentifierListCwtClaimsOptions): void {
    try {
      super.verifyClaims({
        ...options,
        expectedSubject: uri,
        requiredClaims: [
          RegisteredCwtClaimKey.Subject,
          RegisteredCwtClaimKey.IssuedAt,
          RegisteredCwtClaimKey.ExpirationTime,
          ...requiredClaims,
        ],
        keyLabels: IdentifierListCwtClaimKey,
      })
    } catch (error) {
      if (error instanceof CwtClaimVerificationError) {
        throw new InvalidRevocationListError(`Identifier list token claim verification failed. ${error.message}`)
      }

      throw error
    }
  }
}
