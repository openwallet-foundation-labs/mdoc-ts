import { cborEncode, zUint8Array } from '@owf/cose'
import z from 'zod'
import type { MdocContext } from '../../context'
import { Handover } from './handover'

const oid4vpDraft18HandoverEncodedSchema = z.tuple([zUint8Array, zUint8Array, z.string()])
const oid4vpDraft18HandoverDecodedSchema = z.object({
  clientIdHash: zUint8Array,
  responseUriHash: zUint8Array,
  nonce: z.string(),
})

export type Oid4vpDraft18HandoverEncodedStructure = z.infer<typeof oid4vpDraft18HandoverEncodedSchema>
export type Oid4vpDraft18HandoverDecodedStructure = z.infer<typeof oid4vpDraft18HandoverDecodedSchema>

export type Oid4vpDraft18HandoverOptions = {
  clientId: string
  responseUri: string
  mdocGeneratedNonce: string
  nonce: string
}

export class Oid4vpDraft18Handover extends Handover<
  Oid4vpDraft18HandoverEncodedStructure,
  Oid4vpDraft18HandoverDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(oid4vpDraft18HandoverEncodedSchema, oid4vpDraft18HandoverDecodedSchema, {
      encode: ({ clientIdHash, responseUriHash, nonce }) =>
        [clientIdHash, responseUriHash, nonce] satisfies Oid4vpDraft18HandoverEncodedStructure,
      decode: ([clientIdHash, responseUriHash, nonce]) => ({ clientIdHash, responseUriHash, nonce }),
    })
  }

  public static async create(options: Oid4vpDraft18HandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const clientIdHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: cborEncode([options.clientId, options.mdocGeneratedNonce]),
    })

    const responseUriHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: cborEncode([options.responseUri, options.mdocGeneratedNonce]),
    })

    return this.fromDecodedStructure({
      clientIdHash,
      responseUriHash,
      nonce: options.nonce,
    })
  }
}
