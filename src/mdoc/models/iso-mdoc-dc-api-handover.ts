import { cborEncode, zUint8Array } from '@owf/cose'
import z from 'zod'
import type { MdocContext } from '../../context'
import { Handover } from './handover'

const isoMdocDcApiHandoverEncodedSchema = z.tuple([z.literal('dcapi'), zUint8Array])
const isoMdocDcApiHandoverDecodedSchema = zUint8Array

export type IsoMdocDcApiHandoverEncodedStructure = z.infer<typeof isoMdocDcApiHandoverEncodedSchema>
export type IsoMdocDcApiHandoverDecodedStructure = z.infer<typeof isoMdocDcApiHandoverDecodedSchema>

export type IsoMdocDcApiHandoverOptions = {
  encryptionInfoBase64Url: string
  origin: string
}

/**
 * Handover for the ISO 18013-7 Annex C `org-iso-mdoc` DC API protocol.
 *
 *   DCAPIHandover = [ "dcapi", SHA-256(CBOR([encInfoB64u, origin])) ]
 */
export class IsoMdocDcApiHandover extends Handover<
  IsoMdocDcApiHandoverEncodedStructure,
  IsoMdocDcApiHandoverDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(isoMdocDcApiHandoverEncodedSchema, isoMdocDcApiHandoverDecodedSchema, {
      encode: (handoverInfoHash) => ['dcapi', handoverInfoHash] satisfies IsoMdocDcApiHandoverEncodedStructure,
      decode: ([, handoverInfoHash]) => handoverInfoHash,
    })
  }

  public static createFromHash(dcApiInfoHash: Uint8Array) {
    return this.fromDecodedStructure(dcApiInfoHash)
  }

  public static async create(options: IsoMdocDcApiHandoverOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const dcapiInfoBytes = cborEncode([options.encryptionInfoBase64Url, options.origin])
    const dcApiInfoHash = await ctx.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: dcapiInfoBytes,
    })
    return this.fromDecodedStructure(dcApiInfoHash)
  }
}
