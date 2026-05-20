import { CborStructure } from '@owf/cose'
import z from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { ErrorCode } from './error-code'

export const errorItemsSchema = z.map(z.string(), z.number())
export type ErrorItemsStructure = Map<DataElementIdentifier, ErrorCode>

export type ErrorItemsOptions = {
  errorItems: ErrorItemsStructure
}

export class ErrorItems extends CborStructure<ErrorItemsStructure> {
  public static override get encodingSchema() {
    return errorItemsSchema
  }

  public static create(options: ErrorItemsOptions) {
    return this.fromDecodedStructure(options.errorItems)
  }
}
