import { CborStructure } from '@owf/cose'
import { z } from 'zod'

// WebApi = [uint, tstr, tstr] - Array structure
const webApiEncodedSchema = z.tuple([z.number(), z.string(), z.string()])

// Easier structure for internal usage in class
const webApiDecodedSchema = z.object({
  version: z.number(),
  issuerUrl: z.string(),
  serverRetrievalToken: z.string(),
})

export type WebApiEncodedStructure = z.infer<typeof webApiEncodedSchema>
export type WebApiDecodedStructure = z.infer<typeof webApiDecodedSchema>
export type WebApiOptions = WebApiDecodedStructure

export class WebApi extends CborStructure<WebApiEncodedStructure, WebApiDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(webApiEncodedSchema, webApiDecodedSchema, {
      encode: ({ version, issuerUrl, serverRetrievalToken }) =>
        [version, issuerUrl, serverRetrievalToken] satisfies WebApiEncodedStructure,
      decode: ([version, issuerUrl, serverRetrievalToken]) => ({
        version,
        issuerUrl,
        serverRetrievalToken,
      }),
    })
  }

  public get version() {
    return this.structure.version
  }

  public get issuerUrl() {
    return this.structure.issuerUrl
  }

  public get serverRetrievalToken() {
    return this.structure.serverRetrievalToken
  }

  public static create(options: WebApiOptions): WebApi {
    return this.fromDecodedStructure(options)
  }
}
