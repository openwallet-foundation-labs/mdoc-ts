import {
  CoseInvalidSignatureError,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  SignatureAlgorithm,
} from '@owf/cose'
import { fetchStatusList, SLException, StatusListCwt, type StatusListInfo } from '@owf/token-status-list'
import type { MdocContext } from '../../context'
import {
  InvalidIdentifierListSignatureError,
  InvalidRevocationListError,
  InvalidSignatureError,
  JwtNotSupportForStatusListError,
  type MdlError,
  NoPublicKeySetOnStatusListError,
  UnableToExtractX5ChainFromCwtError,
  UnableToExtractX5ChainFromIdentifierListError,
} from '../errors'
import { IdentifierListCwt } from './identifier-list-cwt'
import type { IdentifierListInfo } from './identifier-list-info'

/**
 * Runs the claim and status checks `@owf/cose` and `@owf/token-status-list` own, translating the
 * errors they raise into the mdoc error hierarchy so that a caller of `IssuerAuth.verify` only ever
 * has to know `MdlError`.
 */
async function asMdlRevocationListError(
  verification: () => Promise<unknown> | unknown,
  /** The error to report a failed signature as. */
  invalidSignatureError: new (message: string) => MdlError
): Promise<void> {
  try {
    await verification()
  } catch (error) {
    if (error instanceof CoseInvalidSignatureError) throw new invalidSignatureError(error.message)
    if (error instanceof SLException) throw new InvalidRevocationListError(error.message)
    throw error
  }
}

/**
 * Establishes the signer of a revocation list: the certificate chain it carries, validated against
 * the mdoc trust anchors, and the public key of its leaf.
 *
 * § 12.3.6.3 requires the chain to travel in the protected header of the CWT: "The CWT shall
 * contain the x5chain in the protected header that contains the certificate or chain of
 * certificates used to verify the signature".
 */
async function verifyRevocationListSigner(
  {
    x5chain,
    algorithm,
    trustedCertificates,
    now,
  }: {
    x5chain: Array<Uint8Array>
    algorithm?: SignatureAlgorithm
    trustedCertificates: Array<Uint8Array>
    now: Date
  },
  ctx: Pick<MdocContext, 'x509'>
) {
  const { chain } = await ctx.x509.verifyCertificateChain({ trustedCertificates, x5chain, now })

  const key = await ctx.x509.getPublicKey({ certificate: x5chain[0], algorithm })
  if (!key) {
    throw new NoPublicKeySetOnStatusListError()
  }

  return { chain, key }
}

export type VerifyStatusListTokenOptions = {
  statusListInfo: Pick<StatusListInfo, 'uri' | 'idx'>
  trustedCertificates: Array<Uint8Array>
  now?: Date
  skewSeconds?: number
  checkFreshness?: boolean
}

export type VerifyStatusListTokenResult = {
  statusListCwt: StatusListCwt
  /** The validated certificate chain of the list signer, leaf first. */
  chain: Array<Uint8Array>
}

/**
 * Fetch and verify the status list a `StatusListInfo` points at.
 *
 * `@owf/token-status-list` owns everything status-list-shaped — fetching and content-type
 * negotiation, the CWT structure, the claim checks and reading a status by index. What lives here
 * is only what that library cannot know about: the mdoc trust anchors and the `MdocContext` crypto
 * callbacks used to establish the signer, and the two rules ISO/IEC 18013-5 § 12.3.6 layers on top
 * of the Token Status List defaults — a mandatory `exp` (§ 12.3.6.3), and `Valid` as the only
 * acceptable status, since § 12.3.6.1 allows "no other status besides 'revoked'".
 *
 * § 12.3.6.3 requires the list to be a Status List Token "in CWT format, since the IssuerAuth
 * structure is a CWT", so a list served as a JWT is rejected rather than verified.
 */
export async function verifyStatusListToken(
  { statusListInfo, trustedCertificates, now = new Date(), skewSeconds, checkFreshness }: VerifyStatusListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
): Promise<VerifyStatusListTokenResult> {
  const { uri, idx } = statusListInfo
  const token = await fetchStatusList({ uri, customFetcher: ctx.fetch, acceptedFormats: ['cwt'] })

  // `fetchStatusList` decides on the response's Content-Type, not on `acceptedFormats`, so a JWT
  // still comes back as a string even though it was not asked for.
  if (typeof token === 'string') {
    throw new JwtNotSupportForStatusListError(
      `The status list at ${uri} was served in JWT format. ISO/IEC 18013-5 § 12.3.6.3 requires a Status List Token in CWT format, which is the only format @owf/mdoc verifies`
    )
  }

  const statusListCwt = StatusListCwt.fromToken(token)

  const x5chain = normalizeX5Chain(statusListCwt.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.X5Chain))
  if (!x5chain) {
    throw new UnableToExtractX5ChainFromCwtError()
  }

  const { chain, key } = await verifyRevocationListSigner(
    { x5chain, algorithm: statusListCwt.algorithm as SignatureAlgorithm | undefined, trustedCertificates, now },
    ctx
  )

  // Signature, claims and the status at `idx`, in one call: the token is only the issuer's if it
  // verifies, so there is nothing to read from it before that.
  await asMdlRevocationListError(
    () =>
      statusListCwt.verify(
        {
          key,
          uri,
          idx,
          now,
          skewSeconds,
          checkIssuedAt: checkFreshness,
          // § 12.3.6.3: "The exp claim shall be present." OPTIONAL in the Token Status List
          // specification, which is why it is required here rather than there.
          requiredClaims: [RegisteredCwtClaimKey.ExpirationTime],
        },
        { sign1: ctx.cose.sign1 }
      ),
    InvalidSignatureError
  )

  return { statusListCwt, chain }
}

export type VerifyIdentifierListTokenOptions = {
  identifierListInfo: Pick<IdentifierListInfo, 'uri' | 'id'>
  trustedCertificates: Array<Uint8Array>
  now?: Date
  skewSeconds?: number
  checkFreshness?: boolean
}

export type VerifyIdentifierListTokenResult = {
  identifierListCwt: IdentifierListCwt
  /** The validated certificate chain of the list signer, leaf first. */
  chain: Array<Uint8Array>
}

/**
 * Fetch and verify the identifier list an `IdentifierListInfo` points at (§ 12.3.6.4):
 * certificate chain, signature, the claim checks § 12.3.6.1 makes binding on both revocation
 * mechanisms, and finally whether the MSO's own identifier appears in it — presence means revoked.
 *
 * The counterpart of {@link verifyStatusListToken}. Unlike a status list, the identifier list is an
 * ISO addition that the Token Status List specification does not describe, so `IdentifierListCwt`
 * lives in this package rather than in `@owf/token-status-list` — built on the same `Cwt`, so the
 * two are verified the same way.
 */
export async function verifyIdentifierListToken(
  {
    identifierListInfo,
    trustedCertificates,
    now = new Date(),
    skewSeconds,
    checkFreshness,
  }: VerifyIdentifierListTokenOptions,
  ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
): Promise<VerifyIdentifierListTokenResult> {
  const { uri, id } = identifierListInfo
  const identifierListCwt = await IdentifierListCwt.fetch(uri, ctx)

  const x5chain = identifierListCwt.x5chain
  if (!x5chain || x5chain.length === 0) {
    throw new UnableToExtractX5ChainFromIdentifierListError()
  }

  const { chain, key } = await verifyRevocationListSigner(
    { x5chain, algorithm: identifierListCwt.algorithm as SignatureAlgorithm | undefined, trustedCertificates, now },
    ctx
  )

  await asMdlRevocationListError(
    () =>
      identifierListCwt.verify(
        { key, uri, id, now, skewSeconds, checkIssuedAt: checkFreshness },
        { sign1: ctx.cose.sign1 }
      ),
    InvalidIdentifierListSignatureError
  )

  return { identifierListCwt, chain }
}

/** COSE_X509 carries either a single certificate or a chain of them (RFC 9360). */
function normalizeX5Chain(x5chain: unknown): Array<Uint8Array> | undefined {
  const chain = x5chain instanceof Uint8Array ? [x5chain] : x5chain
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((c) => c instanceof Uint8Array)) return undefined
  return chain
}
