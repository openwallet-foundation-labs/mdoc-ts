import {
  type AnyCwt,
  Cwt,
  type CwtOptions,
  type CwtStaticThis,
  type CwtStructures,
  type CwtVerifyContext,
  type CwtVerifyOptions,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  TypedMap,
  type UnprotectedHeaderOptions,
  type UnprotectedHeaders,
} from '@owf/cose'
import { hex, isMediaType } from '@owf/identity-common'
import type { MdocContext } from '../../context'
import { IdentifierFoundInRevokedListError, InvalidRevocationListError } from '../errors'
import { IdentifierListCwtProtectedHeaders, MediaTypes } from './identifier-list-cwt-headers'
import {
  type CreateIdentifierListCwtPayloadOptions,
  IdentifierListCwtClaimKey,
  IdentifierListCwtPayload,
} from './identifier-list-cwt-payload'

export type IdentifierListCwtOptions = Omit<
  CwtOptions<IdentifierListCwtPayload, IdentifierListCwtProtectedHeaders>,
  'payload' | 'protectedHeaders'
> & {
  payload: IdentifierListCwtPayload | CreateIdentifierListCwtPayloadOptions

  /**
   * The protected headers. `typ` (16) is set to the identifier list media type when absent, so only
   * the one value it is allowed to have has to be supplied.
   */
  protectedHeaders?: IdentifierListCwtProtectedHeaders | ProtectedHeaders | Map<number, unknown>

  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeaderOptions['unprotectedHeaders']
}

/**
 * Builds the protected headers of an identifier list CWT, defaulting `typ` (16) to the identifier
 * list media type. Validated against {@link IdentifierListCwtProtectedHeaders}, so a `typ` that is
 * present but says the token is something else is rejected here rather than silently overwritten.
 */
function identifierListProtectedHeaders(
  protectedHeaders: IdentifierListCwtOptions['protectedHeaders']
): IdentifierListCwtProtectedHeaders {
  if (protectedHeaders instanceof IdentifierListCwtProtectedHeaders) return protectedHeaders

  const headers = new Map<number, unknown>(
    protectedHeaders instanceof ProtectedHeaders ? protectedHeaders.decodedStructure : protectedHeaders
  )
  if (headers.get(RegisteredCwtHeaderClaimKey.Typ) === undefined) {
    headers.set(RegisteredCwtHeaderClaimKey.Typ, MediaTypes.IdentifierListCwt)
  }

  return IdentifierListCwtProtectedHeaders.fromDecodedStructure(TypedMap.fromMap(headers))
}

/**
 * A revocation list token in CWT format that enumerates revoked MSO identifiers, rather than
 * indexing statuses by position (ISO/IEC 18013-5 second edition § 12.3.6.4). Presence of an
 * identifier means the MSO carrying it is revoked; absence means it is valid.
 *
 * The counterpart of `StatusListCwt` from `@owf/token-status-list`, and built the same way: the
 * claims set and protected headers validate themselves, and this class only names them and adds
 * what is specific to an identifier list.
 */
export class IdentifierListCwt extends Cwt<IdentifierListCwtPayload, IdentifierListCwtProtectedHeaders> {
  public constructor(options: IdentifierListCwtOptions) {
    super({
      ...options,
      protectedHeaders: identifierListProtectedHeaders(options.protectedHeaders),
      payload:
        options.payload instanceof IdentifierListCwtPayload
          ? options.payload
          : IdentifierListCwtPayload.create(options.payload),
    })
  }

  /**
   * Decodes an identifier list CWT from a tagged COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) token.
   *
   * @throws CwtPayloadDecodeError if the payload is not a valid identifier list claims set.
   * @throws ZodValidationError if the protected headers do not carry the identifier list `typ`.
   */
  public static override fromToken<T extends AnyCwt>(this: CwtStaticThis<T>, token: Uint8Array): T {
    // NOTE: `super.fromToken`, not `Cwt.fromToken`: the base implementation constructs `this`, so a
    // subclass of IdentifierListCwt is what comes back. The cast is because TypeScript resolves
    // `super.fromToken` against the base class, and cannot see that `T` is made of these structures.
    return super.fromToken(token, {
      payload: IdentifierListCwtPayload,
      protectedHeaders: IdentifierListCwtProtectedHeaders,
    } as unknown as CwtStructures<T>) as T
  }

  /**
   * Fetches the identifier list published at `uri`.
   *
   * The counterpart of `fetchStatusList`, which the Token Status List specification's own media
   * type has; an identifier list is an ISO addition that `@owf/token-status-list` does not know
   * about, so the content type negotiation for it lives here.
   */
  public static async fetch(uri: string, ctx: Pick<MdocContext, 'fetch'>): Promise<IdentifierListCwt> {
    const fetcher = ctx.fetch ?? fetch
    const response = await fetcher(uri, { headers: { Accept: MediaTypes.IdentifierListCwt } })

    if (!response.ok) {
      throw new InvalidRevocationListError(`Identifier list fetch at ${uri} failed with status '${response.status}'`)
    }

    // Token Status List § 8.2, applied to the identifier list media type by § 12.3.6.4. A response
    // without a Content-Type is let through — the token itself carries the media type in `typ`, and
    // is rejected there if it is not an identifier list.
    const contentType = response.headers.get('Content-Type')
    if (contentType !== null && !isMediaType(contentType, MediaTypes.IdentifierListCwt)) {
      throw new InvalidRevocationListError(
        `Identifier list at ${uri} was served as '${contentType}', expected '${MediaTypes.IdentifierListCwt}'`
      )
    }

    return IdentifierListCwt.fromToken(new Uint8Array(await response.arrayBuffer()))
  }

  /** Leaf certificate and chain from the CWT's protected `x5chain` header, normalized to an array. */
  public get x5chain(): Array<Uint8Array> | undefined {
    return this.protectedHeaders.x5chain
  }

  /** True when `id` appears in the published list, and the MSO carrying it is therefore revoked. */
  public includes(id: Uint8Array): boolean {
    return this.payload.identifierList.includes(id)
  }

  /**
   * Verify the token completely: its signature or authentication tag, its claims, and — when `id`
   * is given — that the MSO carrying that identifier has not been revoked. The counterpart of
   * `StatusListCwt.verify`, which takes the `idx` into the status list where this takes the `id`
   * from the MSO's `IdentifierListInfo`.
   *
   * @throws CoseInvalidSignatureError if the signature or authentication tag does not verify.
   * @throws InvalidRevocationListError if the claims do not.
   * @throws IdentifierFoundInRevokedListError if `id` is on the list.
   */
  public override async verify(
    { id, ...options }: CwtVerifyOptions<IdentifierListCwtPayload> & { id?: Uint8Array },
    ctx: CwtVerifyContext
  ): Promise<void> {
    await super.verify(options, ctx)

    if (id !== undefined) this.verifyStatus(id)
  }

  /**
   * Verify that `id` is not on this list, without verifying the remaining claims or the signature.
   *
   * @throws IdentifierFoundInRevokedListError if it is, which per § 12.3.6.4 means the MSO carrying
   *   it is revoked.
   */
  public verifyStatus(id: Uint8Array): void {
    if (this.includes(id)) {
      throw new IdentifierFoundInRevokedListError(
        `Identifier ${hex.encode(id)} found in the revoked identifier list at '${this.payload.subject}'`
      )
    }
  }
}

export { IdentifierListCwtClaimKey }
