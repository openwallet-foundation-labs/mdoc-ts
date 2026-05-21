import { CborStructure, typedMap } from '@owf/cose'
import { z } from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DocType } from './doctype'
import type { IntentToRetain } from './intent-to-retain'
import type { Namespace } from './namespace'

const namespacesSchema = z.map(z.string(), z.map(z.string(), z.boolean()))

// Zod schema for ItemsRequest
const itemsRequestSchema = typedMap([
  ['docType', z.string()],
  ['nameSpaces', namespacesSchema],
] as const)

export type ItemsRequestEncodedStructure = z.input<typeof itemsRequestSchema>
export type ItemsRequestDecodedStructure = z.output<typeof itemsRequestSchema>

type NamespacesStructure = z.infer<typeof namespacesSchema>

export type ItemsRequestOptions = {
  docType: DocType
  namespaces:
    | NamespacesStructure
    // We allow record when creating for easier usage
    | Record<Namespace, Record<DataElementIdentifier, IntentToRetain>>
}

export class ItemsRequest extends CborStructure<ItemsRequestEncodedStructure, ItemsRequestDecodedStructure> {
  public static override get encodingSchema() {
    return itemsRequestSchema
  }

  public get docType() {
    return this.structure.get('docType')
  }

  public get namespaces() {
    return this.structure.get('nameSpaces')
  }

  public static create(options: ItemsRequestOptions): ItemsRequest {
    const namespaces =
      options.namespaces instanceof Map
        ? options.namespaces
        : new Map(Object.entries(options.namespaces).map(([ns, inner]) => [ns, new Map(Object.entries(inner))]))

    const structure = new Map<unknown, unknown>([
      ['docType', options.docType],
      ['nameSpaces', namespaces],
    ])

    return this.fromEncodedStructure(structure)
  }
}
