import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { TypedMap, typedMap } from '../../utils'
import { DeviceSigned, type DeviceSignedEncodedStructure } from './device-signed'
import type { DocType } from './doctype'
import type { ErrorItems } from './error-items'
import { IssuerSigned, type IssuerSignedEncodedStructure } from './issuer-signed'
import type { Namespace } from './namespace'

const documentSchema = typedMap([
  ['docType', z.string()],
  ['issuerSigned', z.instanceof(IssuerSigned)],
  ['deviceSigned', z.instanceof(DeviceSigned)],
  ['errors', z.map(z.string(), z.unknown()).exactOptional()],
] as const)

export type DocumentDecodedStructure = z.output<typeof documentSchema>
export type DocumentEncodedStructure = z.input<typeof documentSchema>

export type DocumentOptions = {
  docType: DocType
  issuerSigned: IssuerSigned
  deviceSigned: DeviceSigned
  errors?: Map<Namespace, ErrorItems>
}

export class Document extends CborStructure<DocumentEncodedStructure, DocumentDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(documentSchema.in, documentSchema.out, {
      decode: (input) => {
        const map: DocumentDecodedStructure = TypedMap.fromMap(input)

        map.set(
          'issuerSigned',
          IssuerSigned.fromEncodedStructure(input.get('issuerSigned') as IssuerSignedEncodedStructure)
        )
        map.set(
          'deviceSigned',
          DeviceSigned.fromEncodedStructure(input.get('deviceSigned') as DeviceSignedEncodedStructure)
        )

        if (input.has('errors')) {
          map.set('errors', input.get('errors') as Map<string, unknown>)
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('issuerSigned', output.get('issuerSigned').encodedStructure)
        map.set('deviceSigned', output.get('deviceSigned').encodedStructure)

        return map
      },
    })
  }

  public get docType() {
    return this.structure.get('docType')
  }

  public get issuerSigned() {
    return this.structure.get('issuerSigned')
  }

  public get deviceSigned() {
    return this.structure.get('deviceSigned')
  }

  public get errors() {
    return this.structure.get('errors')
  }

  public getIssuerNamespace(namespace: Namespace) {
    const issuerSigned = this.structure.get('issuerSigned')
    const issuerNamespaces = issuerSigned?.issuerNamespaces?.issuerNamespaces

    if (!issuerNamespaces) {
      return undefined
    }

    return issuerNamespaces.get(namespace)
  }

  public static create(options: DocumentOptions): Document {
    const map: DocumentDecodedStructure = new TypedMap([
      ['docType', options.docType],
      ['issuerSigned', options.issuerSigned],
      ['deviceSigned', options.deviceSigned],
    ])
    if (options.errors) {
      map.set('errors', options.errors)
    }
    return this.fromDecodedStructure(map)
  }
}
