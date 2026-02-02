import z from 'zod'
import type { MdocContext } from '../../context'
import { zUint8Array } from '../../utils/zod'
import { Handover } from './handover'
import type { Oid4vpIaeHandoverInfo } from './oid4vp-iae-handover-info'

const oid4vpIaeHandoverEncodedSchema = z.tuple([z.literal('OpenID4VCIIAEHandover'), zUint8Array])
const oid4vpIaeHandoverDecodedSchema = zUint8Array

export type Oid4vpIaeHandoverEncodedStructure = z.infer<typeof oid4vpIaeHandoverEncodedSchema>
export type Oid4vpIaeHandoverDecodedStructure = z.infer<typeof oid4vpIaeHandoverDecodedSchema>

export type Oid4vpIaeHandoverOptions = {
  oid4vpIaeHandoverInfo: Oid4vpIaeHandoverInfo
}

export class Oid4vpIaeHandover extends Handover<Oid4vpIaeHandoverEncodedStructure, Oid4vpIaeHandoverDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(oid4vpIaeHandoverEncodedSchema, oid4vpIaeHandoverDecodedSchema, {
      encode: (handoverInfoHash) =>
        ['OpenID4VCIIAEHandover', handoverInfoHash] satisfies Oid4vpIaeHandoverEncodedStructure,
      decode: ([, handoverInfoHash]) => handoverInfoHash,
    })
  }

  public static createFromHash(oid4vpIaeHandoverInfoHash: Uint8Array) {
    return this.fromDecodedStructure(oid4vpIaeHandoverInfoHash)
  }

  public static async create(options: Oid4vpIaeHandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const oid4vpIaeHandoverInfoHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: options.oid4vpIaeHandoverInfo.encode(),
    })

    return this.fromDecodedStructure(oid4vpIaeHandoverInfoHash)
  }
}
