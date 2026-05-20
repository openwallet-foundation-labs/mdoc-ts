import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'

// Zod schema for DeviceSignedItems
export const deviceSignedItemsSchema = z.map(z.string(), z.unknown())

export type DeviceSignedItemsStructure = z.infer<typeof deviceSignedItemsSchema>

export type DeviceSignedItemsOptions = {
  deviceSignedItems: Map<DataElementIdentifier, DataElementValue>
}

export class DeviceSignedItems extends CborStructure<DeviceSignedItemsStructure> {
  public static override get encodingSchema() {
    return deviceSignedItemsSchema
  }

  public get deviceSignedItems() {
    return this.structure
  }

  public static create(options: DeviceSignedItemsOptions): DeviceSignedItems {
    return this.fromEncodedStructure(options.deviceSignedItems)
  }
}
