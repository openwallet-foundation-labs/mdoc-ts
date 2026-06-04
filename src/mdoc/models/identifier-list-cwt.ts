import {
  type CoseKey,
  Cwt,
  cborDecode,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  type Sign1Context,
  type SignatureAlgorithm,
} from '@owf/cose'
import { StatusListCwtClaimKey } from '@owf/token-status-list'
import type { MdocContext } from '../../context'
import {
  IdentifierListCwtClaimKey,
  IdentifierListCwtPayload,
  type IdentifierListCwtPayloadEncodedStructure,
} from './identifier-list-cwt-payload'

/**
 * Signed CWT carrying the list of revoked MSO identifiers (ISO/IEC 18013-5
 * second edition § 12.3.6). The payload is decoded as
 * `IdentifierListCwtPayload`; signature verification mirrors `StatusListCwt`.
 */
export class IdentifierListCwt {
  private constructor(
    private readonly cwt: Cwt,
    public readonly payload: IdentifierListCwtPayload
  ) {}

  public static fromBytes(bytes: Uint8Array): IdentifierListCwt {
    const cwt = Cwt.fromToken(bytes)
    if (!cwt.payload) {
      throw new Error('IdentifierList CWT has no payload')
    }
    const decoded = cborDecode(cwt.payload, { unwrapTopLevelDataItem: false }) as Map<unknown, unknown>
    // § 12.3.6.4: "The StatusList claim shall not be present in the CWT
    // claims set" for an identifier-list CWT. The `typ` claim's presence
    // and value are enforced by `IdentifierListCwtPayload`'s schema.
    if (decoded.has(StatusListCwtClaimKey.StatusList)) {
      throw new Error('IdentifierList CWT must not contain a StatusList claim (ISO 18013-5 § 12.3.6.4)')
    }
    const payload = IdentifierListCwtPayload.fromEncodedStructure(
      decoded as unknown as IdentifierListCwtPayloadEncodedStructure
    )
    return new IdentifierListCwt(cwt, payload)
  }

  public static async fetch(uri: string, ctx: Pick<MdocContext, 'fetch'>): Promise<IdentifierListCwt> {
    const fetcher = ctx.fetch ?? fetch
    const response = await fetcher(uri, {
      headers: { Accept: 'application/identifierlist+cwt' },
    })
    if (!response.ok) {
      throw new Error(`Identifier list fetch failed: ${response.status}`)
    }
    return IdentifierListCwt.fromBytes(new Uint8Array(await response.arrayBuffer()))
  }

  public get protectedHeaders(): ProtectedHeaders | undefined {
    const h = this.cwt.protectedHeaders
    return h instanceof ProtectedHeaders ? h : undefined
  }

  /** Leaf cert + chain from the CWT's protected x5chain header, normalized to an array. */
  public get x5chain(): Array<Uint8Array> | undefined {
    const x5c = this.protectedHeaders?.headers?.get(RegisteredCwtHeaderClaimKey.X5Chain) as
      | Uint8Array
      | Uint8Array[]
      | undefined
    if (x5c instanceof Uint8Array) return [x5c]
    if (Array.isArray(x5c) && x5c.every((e) => e instanceof Uint8Array)) return x5c
    return undefined
  }

  public get algorithm(): SignatureAlgorithm | undefined {
    return this.protectedHeaders?.headers?.get(RegisteredCwtHeaderClaimKey.Algorithm) as SignatureAlgorithm | undefined
  }

  /** Verify the COSE_Sign1 signature against the provided public key. */
  public async verifySignature(options: { key: CoseKey }, ctx: Pick<Sign1Context, 'verify'>): Promise<boolean> {
    return this.cwt.asSign1.verifySignature(options, ctx)
  }

  /** True when `id` appears in the published list (and the credential is therefore revoked). */
  public includes(id: Uint8Array): boolean {
    return this.payload.identifierList.includes(id)
  }
}

export { IdentifierListCwtClaimKey }
