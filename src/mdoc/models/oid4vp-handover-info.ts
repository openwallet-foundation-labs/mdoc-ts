import { CborStructure } from '@owf/cose'
import z from 'zod'
import { zUint8Array } from '../../utils/zod'

const oid4vpHandoverInfoEncodedSchema = z.tuple([z.string(), z.string(), zUint8Array.nullable(), z.string()])
const oid4vpHandoverInfoDecodedSchema = z.object({
  clientId: z.string(),
  nonce: z.string(),
  jwkThumbprint: zUint8Array.nullable(),
  responseUri: z.string(),
})

export type Oid4vpHandoverInfoEncodedStructure = z.infer<typeof oid4vpHandoverInfoEncodedSchema>
export type Oid4vpHandoverInfoDecodedStructure = z.infer<typeof oid4vpHandoverInfoDecodedSchema>

export type Oid4vpHandoverInfoOptions = {
  clientId: string
  nonce: string
  jwkThumbprint?: Uint8Array
  responseUri: string
}

export class Oid4vpHandoverInfo extends CborStructure<
  Oid4vpHandoverInfoEncodedStructure,
  Oid4vpHandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(oid4vpHandoverInfoEncodedSchema, oid4vpHandoverInfoDecodedSchema, {
      encode: ({ clientId, nonce, jwkThumbprint, responseUri }) =>
        [clientId, nonce, jwkThumbprint, responseUri] satisfies Oid4vpHandoverInfoEncodedStructure,
      decode: ([clientId, nonce, jwkThumbprint, responseUri]) => ({ clientId, nonce, jwkThumbprint, responseUri }),
    })
  }

  public get clientId() {
    return this.structure.clientId
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get jwkThumbprint() {
    return this.structure.jwkThumbprint
  }

  public get responseUri() {
    return this.structure.responseUri
  }

  public static create(options: Oid4vpHandoverInfoOptions) {
    return this.fromDecodedStructure({
      clientId: options.clientId,
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint ?? null,
      responseUri: options.responseUri,
    })
  }
}
