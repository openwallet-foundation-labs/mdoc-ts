import { zUint8Array } from '@owf/cose'
import z from 'zod'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpDcApiDraft24HandoverInfo } from './oid4vp-dc-api-draft24-handover-info'
import type { Oid4vpDcApiHandoverInfo } from './oid4vp-dc-api-handover-info'

const oid4vpDcApiHandoverEncodedSchema = z.tuple([z.literal('OpenID4VPDCAPIHandover'), zUint8Array])
const oid4vpDcApiHandoverDecodedSchema = zUint8Array

export type Oid4vpDcApiHandoverEncodedStructure = z.infer<typeof oid4vpDcApiHandoverEncodedSchema>
export type Oid4vpDcApiHandoverDecodedStructure = z.infer<typeof oid4vpDcApiHandoverDecodedSchema>

export type Oid4vpDcApiHandoverOptions = {
  oid4vpDcApiHandoverInfo: Oid4vpDcApiHandoverInfo | Oid4vpDcApiDraft24HandoverInfo
}

export class Oid4vpDcApiHandover extends Handover<
  Oid4vpDcApiHandoverEncodedStructure,
  Oid4vpDcApiHandoverDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(oid4vpDcApiHandoverEncodedSchema, oid4vpDcApiHandoverDecodedSchema, {
      encode: (handoverInfoHash) =>
        ['OpenID4VPDCAPIHandover', handoverInfoHash] satisfies Oid4vpDcApiHandoverEncodedStructure,
      decode: ([, handoverInfoHash]) => handoverInfoHash,
    })
  }

  public static createFromHash(oid4vpDcApiHandoverInfoHash: Uint8Array) {
    return this.fromDecodedStructure(oid4vpDcApiHandoverInfoHash)
  }

  public static async create(options: Oid4vpDcApiHandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const oid4vpDcApiHandoverInfoHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: options.oid4vpDcApiHandoverInfo.encode(),
    })

    return this.fromDecodedStructure(oid4vpDcApiHandoverInfoHash)
  }
}
