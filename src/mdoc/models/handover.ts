import { CborStructure, type DecodedStructureType, type EncodedStructureType } from '@owf/cose'

export abstract class Handover<EncodedStructure = unknown, DecodedStructure = EncodedStructure> extends CborStructure<
  EncodedStructure,
  DecodedStructure
> {
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static tryDecodeHandover<T extends Handover<any, any>>(
    this: {
      // biome-ignore lint/suspicious/noExplicitAny: no explanation
      new (structure: any): T
      fromEncodedStructure: (encodedStructure: EncodedStructureType<T>) => { decodedStructure: DecodedStructureType<T> }
    },
    structure: unknown
  ): T | null {
    try {
      // May feel weird, but using new this makes TypeScript understand we may return a subclass
      return new this(this.fromEncodedStructure(structure as EncodedStructureType<T>).decodedStructure)
    } catch {
      // We just return null if the parsing fails
      return null
    }
  }

  /**
   * Whether this handover structure requires a reader key. Can
   * be overridden in extending handover classes.
   */
  public get requiresReaderKey() {
    return false
  }

  /**
   * Whether this handover structure requires device engagement structure. Can
   * be overridden in extending handover classes.
   */
  public get requiresDeviceEngagement() {
    return false
  }
}
