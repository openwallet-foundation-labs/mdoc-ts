import { CborStructure, typedMap, zUint8Array } from '@owf/cose'
import { compareBytes } from '@owf/identity-common'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'
import type { IssuerAuth } from './issuer-auth'
import type { Namespace } from './namespace'

// IssuerSignedItem uses string keys per spec:
// IssuerSignedItem = {
//   "digestID" : uint,
//   "random" : bstr,
//   "elementIdentifier" : DataElementIdentifier,
//   "elementValue" : DataElementValue
// }
export const issuerSignedItemSchema = typedMap([
  ['digestID', z.number()],
  ['random', zUint8Array],
  ['elementIdentifier', z.string()],
  ['elementValue', z.unknown()],
])

export type IssuerSignedItemEncodedStructure = z.input<typeof issuerSignedItemSchema>
export type IssuerSignedItemDecodedStructure = z.output<typeof issuerSignedItemSchema>

// NOTE: Id vs ID above (user-facing API uses digestId, CBOR uses digestID)
export type IssuerSignedItemOptions = {
  digestId: number
  random: Uint8Array
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

export class IssuerSignedItem extends CborStructure<
  IssuerSignedItemEncodedStructure,
  IssuerSignedItemDecodedStructure
> {
  public static override get encodingSchema() {
    return issuerSignedItemSchema
  }

  public get random() {
    return this.structure.get('random')
  }

  public get elementIdentifier() {
    return this.structure.get('elementIdentifier')
  }

  public get elementValue() {
    return this.structure.get('elementValue')
  }

  public get digestId() {
    return this.structure.get('digestID')
  }

  public async isValid(namespace: Namespace, issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'crypto'>) {
    const digest = await ctx.crypto.digest({
      digestAlgorithm: issuerAuth.mobileSecurityObject.digestAlgorithm,
      bytes: this.encode({ asDataItem: true }),
    })

    const valueDigests = issuerAuth.mobileSecurityObject.valueDigests.valueDigests
    const digests = valueDigests.get(namespace)

    if (!digests) {
      return false
    }

    const expectedDigest = digests.get(this.digestId)

    return expectedDigest !== undefined && compareBytes(digest, expectedDigest)
  }

  public matchCertificate(issuerAuth: IssuerAuth, ctx: Pick<MdocContext, 'x509'>) {
    if (this.elementIdentifier === 'issuing_country') {
      return this.elementValue === issuerAuth.getIssuingCountry(ctx)
    }

    if (this.elementIdentifier === 'issuing_jurisdiction') {
      return this.elementValue === issuerAuth.getIssuingStateOrProvince(ctx)
    }

    return false
  }

  public static fromOptions(options: IssuerSignedItemOptions) {
    const map = new Map([
      ['digestID', options.digestId],
      ['random', options.random],
      ['elementIdentifier', options.elementIdentifier],
      ['elementValue', options.elementValue],
    ])
    return this.fromEncodedStructure(map)
  }
}
