import { CborStructure, typedMap, zUint8Array } from '@owf/cose'
import { z } from 'zod'

// Zod schema for SessionData
const sessionDataSchema = typedMap([
  ['status', z.number().exactOptional()],
  ['data', zUint8Array.exactOptional()],
] as const)

export type SessionDataEncodedStructure = z.input<typeof sessionDataSchema>
export type SessionDataDecodedStructure = z.output<typeof sessionDataSchema>

export type SessionDataOptions = {
  status?: number
  data?: Uint8Array
}

export class SessionData extends CborStructure<SessionDataEncodedStructure, SessionDataDecodedStructure> {
  public static override get encodingSchema() {
    return sessionDataSchema
  }

  public get status() {
    return this.structure.get('status')
  }

  public get data() {
    return this.structure.get('data')
  }

  public static create(options: SessionDataOptions) {
    const structure = new Map()

    if (options.status !== undefined) structure.set('status', options.status)
    if (options.data !== undefined) structure.set('data', options.data)

    return this.fromEncodedStructure(structure)
  }
}
