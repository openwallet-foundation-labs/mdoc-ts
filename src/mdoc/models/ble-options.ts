import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { typedMap } from '../../utils'
import { zUint8Array } from '../../utils/zod'

enum BleOptionsKeys {
  PeripheralServerMode = 0,
  CentralClientMode = 1,
  PeripheralServerModeUuid = 10,
  CentralClientModeUuid = 11,
  PeripheralServerModeDeviceAddress = 20,
}

// BleOptions uses integer keys per spec:
// BleOptions = {
//   0 : bool,   // Supports peripheral server mode
//   1 : bool,   // Supports central client mode
//   ? 10 : bstr, // UUID for peripheral server mode
//   ? 11 : bstr, // UUID for central client mode
//   ? 20 : bstr  // BLE Device Address
// }
const bleOptionsSchema = typedMap([
  [BleOptionsKeys.PeripheralServerMode, z.boolean()],
  [BleOptionsKeys.CentralClientMode, z.boolean()],
  [BleOptionsKeys.PeripheralServerModeUuid, zUint8Array.exactOptional()],
  [BleOptionsKeys.CentralClientModeUuid, zUint8Array.exactOptional()],
  [BleOptionsKeys.PeripheralServerModeDeviceAddress, zUint8Array.exactOptional()],
] as const)

export type BleOptionsEncodedStructure = z.input<typeof bleOptionsSchema>
export type BleOptionsDecodedStructure = z.output<typeof bleOptionsSchema>

export type BleOptionsOptions = {
  peripheralServerMode: boolean
  centralClientMode: boolean
  peripheralServerModeUuid?: Uint8Array
  centralClientModeUuid?: Uint8Array
  peripheralServerModeDeviceAddress?: Uint8Array
}

export class BleOptions extends CborStructure<BleOptionsEncodedStructure, BleOptionsDecodedStructure> {
  public static override get encodingSchema() {
    return bleOptionsSchema
  }

  public get peripheralServerMode() {
    return this.structure.get(BleOptionsKeys.PeripheralServerMode)
  }

  public get centralClientMode() {
    return this.structure.get(BleOptionsKeys.CentralClientMode)
  }

  public get peripheralServerModeUuid() {
    return this.structure.get(BleOptionsKeys.PeripheralServerModeUuid)
  }

  public get centralClientModeUuid() {
    return this.structure.get(BleOptionsKeys.CentralClientModeUuid)
  }

  public get peripheralServerModeDeviceAddress() {
    return this.structure.get(BleOptionsKeys.PeripheralServerModeDeviceAddress)
  }

  public static create(options: BleOptionsOptions): BleOptions {
    const map = new Map<number, unknown>([
      [BleOptionsKeys.PeripheralServerMode, options.peripheralServerMode],
      [BleOptionsKeys.CentralClientMode, options.centralClientMode],
    ])

    if (options.peripheralServerModeUuid !== undefined) {
      map.set(BleOptionsKeys.PeripheralServerModeUuid, options.peripheralServerModeUuid)
    }

    if (options.centralClientModeUuid !== undefined) {
      map.set(BleOptionsKeys.CentralClientModeUuid, options.centralClientModeUuid)
    }

    if (options.peripheralServerModeDeviceAddress !== undefined) {
      map.set(BleOptionsKeys.PeripheralServerModeDeviceAddress, options.peripheralServerModeDeviceAddress)
    }

    return this.fromEncodedStructure(map)
  }
}
