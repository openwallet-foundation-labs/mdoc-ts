import { CborStructure } from '@owf/cose'
import { z } from 'zod'

// KeyInfo uses integer keys (Map<number, unknown>)
// Per spec: KeyInfo = { * int => any }
const keyInfoSchema = z.map(z.number(), z.unknown())

export type KeyInfoEncodedStructure = z.input<typeof keyInfoSchema>
export type KeyInfoDecodedStructure = z.output<typeof keyInfoSchema>

export type KeyInfoOptions = {
  keyInfo: Map<number, unknown>
}

export class KeyInfo extends CborStructure<KeyInfoEncodedStructure, KeyInfoDecodedStructure> {
  public static override get encodingSchema() {
    return keyInfoSchema
  }

  public get keyInfo() {
    return this.structure
  }

  public static create(options: KeyInfoOptions): KeyInfo {
    return this.fromEncodedStructure(options.keyInfo)
  }
}
