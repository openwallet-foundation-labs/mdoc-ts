import { CborStructure, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { Namespace } from './namespace'

const keyAuthorizationsSchema = typedMap([
  ['nameSpaces', z.array(z.string()).exactOptional()],
  ['dataElements', z.map(z.string(), z.array(z.string())).exactOptional()],
] as const)

export type KeyAuthorizationsEncodedStructure = z.input<typeof keyAuthorizationsSchema>
export type KeyAuthorizationsDecodedStructure = z.output<typeof keyAuthorizationsSchema>

export type KeyAuthorizationsOptions = {
  namespaces?: Array<Namespace>
  dataElements?: Map<Namespace, Array<DataElementIdentifier>>
}

export class KeyAuthorizations extends CborStructure<
  KeyAuthorizationsEncodedStructure,
  KeyAuthorizationsDecodedStructure
> {
  public static override get encodingSchema() {
    return keyAuthorizationsSchema
  }

  public get namespaces() {
    return this.structure.get('nameSpaces')
  }

  public get dataElements() {
    return this.structure.get('dataElements')
  }

  public static create(options: KeyAuthorizationsOptions): KeyAuthorizations {
    const map: KeyAuthorizationsDecodedStructure = new TypedMap([])

    if (options.namespaces !== undefined) {
      map.set('nameSpaces', options.namespaces)
    }

    if (options.dataElements !== undefined) {
      map.set('dataElements', options.dataElements)
    }

    return this.fromDecodedStructure(map)
  }
}
