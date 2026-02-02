import z from 'zod'
import { CborStructure } from '../../cbor'
import { zUint8Array } from '../../utils/zod'

const oid4vpIaeHandoverInfoEncodedSchema = z.tuple([z.string(), z.string(), zUint8Array.nullable()])
const oid4vpIaeHandoverInfoDecodedSchema = z.object({
  interactiveAuthorizationEndpoint: z.string(),
  nonce: z.string(),
  jwkThumbprint: zUint8Array.nullable(),
})

export type Oid4vpIaeHandoverInfoEncodedStructure = z.infer<typeof oid4vpIaeHandoverInfoEncodedSchema>
export type Oid4vpIaeHandoverInfoDecodedStructure = z.infer<typeof oid4vpIaeHandoverInfoDecodedSchema>

export type Oid4vpIaeHandoverInfoOptions = {
  interactiveAuthorizationEndpoint: string
  nonce: string
  jwkThumbprint?: Uint8Array
}

export class Oid4vpIaeHandoverInfo extends CborStructure<
  Oid4vpIaeHandoverInfoEncodedStructure,
  Oid4vpIaeHandoverInfoDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(oid4vpIaeHandoverInfoEncodedSchema, oid4vpIaeHandoverInfoDecodedSchema, {
      encode: ({ interactiveAuthorizationEndpoint, nonce, jwkThumbprint }) =>
        [interactiveAuthorizationEndpoint, nonce, jwkThumbprint] satisfies Oid4vpIaeHandoverInfoEncodedStructure,
      decode: ([interactiveAuthorizationEndpoint, nonce, jwkThumbprint]) => ({
        interactiveAuthorizationEndpoint,
        nonce,
        jwkThumbprint,
      }),
    })
  }

  public get interactiveAuthorizationEndpoint() {
    return this.structure.interactiveAuthorizationEndpoint
  }

  public get nonce() {
    return this.structure.nonce
  }

  public get jwkThumbprint() {
    return this.structure.jwkThumbprint
  }

  public static create(options: Oid4vpIaeHandoverInfoOptions) {
    return this.fromDecodedStructure({
      interactiveAuthorizationEndpoint: options.interactiveAuthorizationEndpoint,
      nonce: options.nonce,
      jwkThumbprint: options.jwkThumbprint ?? null,
    })
  }
}
