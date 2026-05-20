import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { ItemsRequest, type ItemsRequestEncodedStructure } from './items-request'
import { SessionTranscript, sessionTranscriptEncodedSchema } from './session-transcript'

const readerAuthenticationEncodedSchema = z.tuple([
  z.literal('ReaderAuthentication'),
  sessionTranscriptEncodedSchema,
  z.instanceof<typeof DataItem<ItemsRequestEncodedStructure>>(DataItem),
])

const readerAuthenticationDecodedSchema = z.object({
  sessionTranscript: z.instanceof(SessionTranscript),
  itemsRequest: z.instanceof(ItemsRequest),
})

export type ReaderAuthenticationDecodedStructure = z.infer<typeof readerAuthenticationDecodedSchema>
export type ReaderAuthenticationEncodedStructure = z.infer<typeof readerAuthenticationEncodedSchema>

export type ReaderAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  itemsRequest: ItemsRequest
}

export class ReaderAuthentication extends CborStructure<
  ReaderAuthenticationEncodedStructure,
  ReaderAuthenticationDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(readerAuthenticationEncodedSchema, readerAuthenticationDecodedSchema, {
      decode: ([, sessionTranscript, itemsRequestDataItem]) => ({
        sessionTranscript: SessionTranscript.fromEncodedStructure(sessionTranscript),
        itemsRequest: ItemsRequest.fromEncodedStructure(itemsRequestDataItem.data),
      }),
      encode: ({ sessionTranscript, itemsRequest }) =>
        [
          'ReaderAuthentication',
          sessionTranscript.encodedStructure,
          DataItem.fromData(itemsRequest.encodedStructure),
        ] satisfies ReaderAuthenticationEncodedStructure,
    })
  }

  public get sessionTranscript() {
    return this.structure.sessionTranscript
  }

  public get itemsRequest() {
    return this.structure.itemsRequest
  }

  public static create(options: ReaderAuthenticationOptions): ReaderAuthentication {
    return this.fromDecodedStructure({
      sessionTranscript: options.sessionTranscript,
      itemsRequest: options.itemsRequest,
    })
  }
}
