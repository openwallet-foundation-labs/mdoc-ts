import { zUint8Array } from '@owf/cose'
import z from 'zod'
import { Handover } from './handover'

const nfcHandoverEncodedSchema = z.tuple([zUint8Array, zUint8Array.nullable()])
const nfcHandoverDecodedSchema = z.object({
  selectMessage: zUint8Array,
  requestMessage: zUint8Array.nullable(),
})

export type NfcHandoverEncodedStructure = z.infer<typeof nfcHandoverEncodedSchema>
export type NfcHandoverDecodedStructure = z.infer<typeof nfcHandoverDecodedSchema>

export type NfcHandoverOptions = {
  selectMessage: Uint8Array
  requestMessage?: Uint8Array
}

export class NfcHandover extends Handover<NfcHandoverEncodedStructure, NfcHandoverDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(nfcHandoverEncodedSchema, nfcHandoverDecodedSchema, {
      encode: ({ selectMessage, requestMessage }) =>
        [selectMessage, requestMessage] satisfies NfcHandoverEncodedStructure,
      decode: ([selectMessage, requestMessage]) => ({ selectMessage, requestMessage }),
    })
  }

  public get selectMessage() {
    return this.structure.selectMessage
  }

  public get requestMessage() {
    return this.structure.requestMessage
  }

  public static create(options: NfcHandoverOptions) {
    return this.fromDecodedStructure({
      requestMessage: options.requestMessage ?? null,
      selectMessage: options.selectMessage,
    })
  }

  public override get requiresReaderKey() {
    return true
  }

  public override get requiresDeviceEngagement() {
    return true
  }
}
