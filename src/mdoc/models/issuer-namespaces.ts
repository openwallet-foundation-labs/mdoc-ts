import { CborStructure, DataItem } from '@owf/cose'
import z from 'zod'
import { IssuerSignedItem, type IssuerSignedItemEncodedStructure } from './issuer-signed-item'

export const issuerNamespacesEncodedSchema = z.map(z.string(), z.array(z.instanceof(DataItem)))
export const issuerNamespacesDecodedSchema = z.map(z.string(), z.array(z.instanceof(IssuerSignedItem)))

export type IssuerNamespacesEncodedStructure = z.infer<typeof issuerNamespacesEncodedSchema>
export type IssuerNamespacesDecodedStructure = z.infer<typeof issuerNamespacesDecodedSchema>

export type IssuerNamespacesOptions = {
  issuerNamespaces: IssuerNamespacesDecodedStructure
}

export class IssuerNamespaces extends CborStructure<
  IssuerNamespacesEncodedStructure,
  IssuerNamespacesDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(issuerNamespacesEncodedSchema, issuerNamespacesDecodedSchema, {
      decode: (encoded) => {
        const issuerNamespaces = new Map<string, IssuerSignedItem[]>()
        encoded.forEach((value, key) => {
          issuerNamespaces.set(
            key,
            value.map((isi) => IssuerSignedItem.fromEncodedStructure(isi.data as IssuerSignedItemEncodedStructure))
          )
        })

        return issuerNamespaces
      },
      encode: (decoded) => {
        const issuerNamespaces = new Map()
        decoded.forEach((value, key) => {
          issuerNamespaces.set(
            key,
            value.map((isi) => DataItem.fromData(isi.encodedStructure))
          )
        })
        return issuerNamespaces
      },
    })
  }

  public get issuerNamespaces() {
    return this.structure
  }

  public getIssuerNamespace(namespace: string) {
    return this.structure.get(namespace)
  }

  public setIssuerNamespace(namespace: string, issuerSignedItems: IssuerSignedItem[]) {
    return this.structure.set(namespace, issuerSignedItems)
  }

  public static create(options: IssuerNamespacesOptions) {
    return this.fromDecodedStructure(options.issuerNamespaces)
  }
}
