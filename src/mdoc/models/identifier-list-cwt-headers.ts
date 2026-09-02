import {
  type CoseHeadersFor,
  extendCoseHeaderClaims,
  ProtectedHeaders,
  protectedHeadersSchema,
  RegisteredCwtHeaderClaimKey,
} from '@owf/cose'
import z from 'zod'

/** CWT media types used by the ISO/IEC 18013-5 revocation mechanisms. */
export enum MediaTypes {
  IdentifierListCwt = 'application/identifierlist+cwt',
}

// § 12.3.6.4: "The value of the type claim shall be 'application/identifierlist+cwt'".
// `typ` is a COSE header parameter (RFC 9596, label 16), not a CWT claim — the same place
// `@owf/token-status-list` writes it on a status list CWT. Required in the protected bucket
// specifically: RFC 9596 forbids `typ` in the unprotected headers, so an unprotected copy is
// not integrity protected, and `Cwt.typ` ignores it.
const identifierListCwtProtectedHeaderClaims = extendCoseHeaderClaims([
  [
    RegisteredCwtHeaderClaimKey.Typ,
    z.literal(MediaTypes.IdentifierListCwt, {
      error: `Typ (protected header 16) shall be '${MediaTypes.IdentifierListCwt}' (ISO 18013-5 § 12.3.6.4)`,
    }),
  ],
] as const)

/**
 * The protected COSE headers of an identifier list CWT (ISO/IEC 18013-5 second edition
 * § 12.3.6.4): the registered COSE header claims, with `typ` (16) required and narrowed to the
 * identifier list media type.
 *
 * `alg` and `x5chain` are already typed by the registered claims, so they are not redeclared.
 */
export class IdentifierListCwtProtectedHeaders extends ProtectedHeaders<
  CoseHeadersFor<typeof identifierListCwtProtectedHeaderClaims>
> {
  public static override get encodingSchema() {
    return protectedHeadersSchema(identifierListCwtProtectedHeaderClaims)
  }

  /**
   * Leaf certificate and chain from the `x5chain` header (RFC 9360 label 33), normalized to an
   * array. § 12.3.6.3 requires it: "The CWT shall contain the x5chain in the protected header".
   */
  public get x5chain(): Array<Uint8Array> | undefined {
    const x5chain = this.headers.get(RegisteredCwtHeaderClaimKey.X5Chain)
    return x5chain instanceof Uint8Array ? [x5chain] : x5chain
  }
}
