import { CborStructure } from '@owf/cose'
import z from 'zod'
import { ErrorItems, errorItemsSchema } from './error-items'

const errorsEncodedSchema = z.map(z.string(), errorItemsSchema)
const errorsDecodedSchema = z.map(z.string(), z.instanceof(ErrorItems))

export type ErrorsEncodedStructure = z.infer<typeof errorsEncodedSchema>
export type ErrorsDecodedStructure = z.infer<typeof errorsDecodedSchema>

export type ErrorsOptions = {
  errors: ErrorsDecodedStructure
}

export class Errors extends CborStructure<ErrorsEncodedStructure, ErrorsDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(errorsEncodedSchema, errorsDecodedSchema, {
      encode: (decoded) => {
        const errorsDecoded: ErrorsEncodedStructure = new Map()

        decoded.forEach((value, key) => {
          errorsDecoded.set(key, value.encodedStructure)
        })

        return errorsDecoded
      },
      decode: (encoded) => {
        const errorsDecoded: ErrorsDecodedStructure = new Map()

        encoded.forEach((value, key) => {
          errorsDecoded.set(key, ErrorItems.fromEncodedStructure(value))
        })

        return errorsDecoded
      },
    })
  }
}
