import { zUint8Array } from '@owf/cose'
import z from 'zod'
import type { MdocContext } from '../../context'
import { Handover } from './handover'
import type { Oid4vpHandoverInfo } from './oid4vp-handover-info'

const oid4vpHandoverEncodedSchema = z.tuple([z.literal('OpenID4VPHandover'), zUint8Array])
const oid4vpHandoverDecodedSchema = zUint8Array

export type Oid4vpHandoverEncodedStructure = z.infer<typeof oid4vpHandoverEncodedSchema>
export type Oid4vpHandoverDecodedStructure = z.infer<typeof oid4vpHandoverDecodedSchema>

export type Oid4vpHandoverOptions = {
  oid4vpHandoverInfo: Oid4vpHandoverInfo
}

export class Oid4vpHandover extends Handover<Oid4vpHandoverEncodedStructure, Oid4vpHandoverDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(oid4vpHandoverEncodedSchema, oid4vpHandoverDecodedSchema, {
      encode: (handoverInfoHash) => ['OpenID4VPHandover', handoverInfoHash] satisfies Oid4vpHandoverEncodedStructure,
      decode: ([, handoverInfoHash]) => handoverInfoHash,
    })
  }

  public get handoverInfoHash() {
    return this.structure
  }

  public static createFromHash(oid4vpHandoverInfoHash: Uint8Array) {
    return this.fromDecodedStructure(oid4vpHandoverInfoHash)
  }

  public static async create(options: Oid4vpHandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const oid4vpHandoverInfoHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: options.oid4vpHandoverInfo.encode(),
    })

    return this.fromDecodedStructure(oid4vpHandoverInfoHash)
  }
}
