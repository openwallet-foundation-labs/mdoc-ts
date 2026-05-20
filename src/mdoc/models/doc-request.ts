import { CborStructure, DataItem } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { ItemsRequest, type ItemsRequestEncodedStructure } from './items-request'
import { ReaderAuth, type ReaderAuthEncodedStructure } from './reader-auth'

const docRequestSchema = typedMap([
  ['itemsRequest', z.instanceof(ItemsRequest)],
  ['readerAuth', z.instanceof(ReaderAuth).exactOptional()],
] as const)

export type DocRequestDecodedStructure = z.output<typeof docRequestSchema>
export type DocRequestEncodedStructure = z.input<typeof docRequestSchema>

export type DocRequestOptions = {
  itemsRequest: ItemsRequest
  readerAuth?: ReaderAuth
}

export class DocRequest extends CborStructure<DocRequestEncodedStructure, DocRequestDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(docRequestSchema.in, docRequestSchema.out, {
      decode: (input) => {
        const map: DocRequestDecodedStructure = TypedMap.fromMap(input)

        const itemsRequestData = input.get('itemsRequest') as DataItem
        map.set(
          'itemsRequest',
          ItemsRequest.fromEncodedStructure(itemsRequestData.data as ItemsRequestEncodedStructure)
        )

        if (input.has('readerAuth')) {
          map.set('readerAuth', ReaderAuth.fromEncodedStructure(input.get('readerAuth') as ReaderAuthEncodedStructure))
        }

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('itemsRequest', DataItem.fromData(output.get('itemsRequest').encodedStructure))

        const readerAuth = output.get('readerAuth')
        if (readerAuth) {
          map.set('readerAuth', readerAuth.encodedStructure)
        }

        return map
      },
    })
  }

  public get itemsRequest() {
    return this.structure.get('itemsRequest')
  }

  public get readerAuth() {
    return this.structure.get('readerAuth')
  }

  public static create(options: DocRequestOptions): DocRequest {
    const map: DocRequestDecodedStructure = new TypedMap([['itemsRequest', options.itemsRequest]])
    if (options.readerAuth) {
      map.set('readerAuth', options.readerAuth)
    }
    return this.fromDecodedStructure(map)
  }
}
