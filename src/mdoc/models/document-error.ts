import { CborStructure } from '@owf/cose'
import { z } from 'zod'

// Zod schema for DocumentError
const documentErrorSchema = z.map(z.string(), z.number())

export type DocumentErrorStructure = z.infer<typeof documentErrorSchema>

export type DocumentErrorOptions = {
  documentError: DocumentErrorStructure
}

export class DocumentError extends CborStructure<DocumentErrorStructure> {
  public static override get encodingSchema() {
    return documentErrorSchema
  }

  /**
   * Map where keys are namespaces and values are error codes
   */
  public get documentError() {
    return this.structure
  }

  public static create(options: DocumentErrorOptions): DocumentError {
    return new DocumentError(options.documentError)
  }
}
