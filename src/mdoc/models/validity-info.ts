import { CborStructure, typedMap } from '@owf/cose'
import { z } from 'zod'

// Zod schema for ValidityInfo validation
// The CBOR date extension (tag 0) handles Date <-> ISO string conversion automatically
// So we just use z.date() and let CBOR handle the encoding/decoding
const validityInfoSchema = typedMap([
  ['signed', z.date()],
  ['validFrom', z.date()],
  ['validUntil', z.date()],
  ['expectedUpdate', z.date().exactOptional()],
])

// Infer structure type from Zod schema (this is the output type after decoding)
export type ValidityInfoEncodedStructure = z.input<typeof validityInfoSchema>
export type ValidityInfoDecodedStructure = z.output<typeof validityInfoSchema>

// Manual options type (user-facing API)
export type ValidityInfoOptions = {
  signed: Date
  validFrom: Date
  validUntil: Date
  expectedUpdate?: Date
}

export class ValidityInfo extends CborStructure<ValidityInfoEncodedStructure, ValidityInfoDecodedStructure> {
  public static override get encodingSchema() {
    return validityInfoSchema
  }

  public get signed() {
    return this.structure.get('signed')
  }

  public get validFrom() {
    return this.structure.get('validFrom')
  }

  public get validUntil() {
    return this.structure.get('validUntil')
  }

  public get expectedUpdate() {
    return this.structure.get('expectedUpdate')
  }

  public isSignedBetweenDates(notBefore: Date, notAfter: Date, skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const notBeforeWithSkew = new Date(notBefore.getTime() - skewMs)
    const notAfterWithSkew = new Date(notAfter.getTime() + skewMs)
    const isWithinRange = this.signed > notBeforeWithSkew && this.signed < notAfterWithSkew
    return isWithinRange
  }

  public isValidUntilAfterNow(now: Date = new Date(), skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const validUntilWithSkew = new Date(this.validUntil.getTime() + skewMs)
    return validUntilWithSkew >= now
  }

  public isValidFromBeforeNow(now: Date = new Date(), skewSeconds = 30): boolean {
    const skewMs = skewSeconds * 1000
    const validFromWithSkew = new Date(this.validFrom.getTime() - skewMs)
    return validFromWithSkew <= now
  }

  public static create(options: ValidityInfoOptions): ValidityInfo {
    const encodedStructure = new Map([
      ['signed', options.signed],
      ['validFrom', options.validFrom],
      ['validUntil', options.validUntil],
    ])

    if (options.expectedUpdate !== undefined) {
      encodedStructure.set('expectedUpdate', options.expectedUpdate)
    }

    return this.fromEncodedStructure(encodedStructure)
  }
}
