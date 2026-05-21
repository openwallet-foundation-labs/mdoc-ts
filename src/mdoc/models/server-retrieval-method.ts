import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import { Oidc, type OidcEncodedStructure } from './oidc'
import { WebApi, type WebApiEncodedStructure } from './web-api'

const serverRetrievalMethodSchema = typedMap([
  ['webApi', z.instanceof(WebApi).exactOptional()],
  ['oidc', z.instanceof(Oidc).exactOptional()],
] as const)

export type ServerRetrievalMethodDecodedStructure = z.output<typeof serverRetrievalMethodSchema>
export type ServerRetrievalMethodEncodedStructure = z.input<typeof serverRetrievalMethodSchema>

export type ServerRetrievalMethodOptions = {
  webApi?: WebApi
  oidc?: Oidc
}

export class ServerRetrievalMethod extends CborStructure<
  ServerRetrievalMethodEncodedStructure,
  ServerRetrievalMethodDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(serverRetrievalMethodSchema.in, serverRetrievalMethodSchema.out, {
      decode: (input) => {
        const map: ServerRetrievalMethodDecodedStructure = TypedMap.fromMap(input)

        if (input.has('webApi')) {
          map.set('webApi', WebApi.fromEncodedStructure(input.get('webApi') as WebApiEncodedStructure))
        }
        if (input.has('oidc')) {
          map.set('oidc', Oidc.fromEncodedStructure(input.get('oidc') as OidcEncodedStructure))
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        const webApi = output.get('webApi')
        if (webApi) {
          map.set('webApi', webApi.encodedStructure)
        }
        const oidc = output.get('oidc')
        if (oidc) {
          map.set('oidc', oidc.encodedStructure)
        }
        return map
      },
    })
  }

  public get webApi() {
    return this.structure.get('webApi')
  }

  public get oidc() {
    return this.structure.get('oidc')
  }

  public static create(options: ServerRetrievalMethodOptions): ServerRetrievalMethod {
    const map: ServerRetrievalMethodDecodedStructure = new TypedMap([])
    if (options.webApi) {
      map.set('webApi', options.webApi)
    }
    if (options.oidc) {
      map.set('oidc', options.oidc)
    }
    return this.fromDecodedStructure(map)
  }
}
