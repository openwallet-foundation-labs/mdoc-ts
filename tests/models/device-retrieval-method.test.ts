import { describe, expect, test } from 'vitest'
import { BleOptions, cborDecode } from '../../src'
import {
  DeviceRetrievalMethod,
  type DeviceRetrievalMethodEncodedStructure,
  DeviceRetrievalMethodType,
} from '../../src/mdoc/models/device-retrieval-method'
import { hex } from '../../src/utils'

const cbor = '830201b900036130f46131f56231315045efef742b2c4837a9a3b0e1d05a6917'

describe('device retrieval method', () => {
  test('parse', () => {
    // NOTE: the test vector above was created incorrectly using an object
    // and thus integer keys were transformed to number. We transform the string
    // keys to numbers, to keep the same test vectors for now, and minimize side effects
    // from the refactor to the stricter parsing
    const deviceRetrievalMethodStructure = cborDecode(hex.decode(cbor)) as Array<unknown>
    const bleOptions = deviceRetrievalMethodStructure[2] as Map<string, unknown>

    const updatedBleOptions = new Map<number, unknown>()
    bleOptions.forEach((value, key) => {
      updatedBleOptions.set(Number(key), value)
    })
    deviceRetrievalMethodStructure[2] = updatedBleOptions

    const deviceRetrievalMethod = DeviceRetrievalMethod.fromEncodedStructure(
      deviceRetrievalMethodStructure as DeviceRetrievalMethodEncodedStructure
    )

    expect(deviceRetrievalMethod.version).toStrictEqual(1)
    expect(deviceRetrievalMethod.type).toStrictEqual(DeviceRetrievalMethodType.Ble)
    expect(deviceRetrievalMethod.retrievalOptions).instanceof(BleOptions)

    const ro = deviceRetrievalMethod.retrievalOptions as BleOptions

    expect(ro.centralClientMode).toStrictEqual(true)
    expect(ro.centralClientModeUuid).toBeDefined()

    expect(ro.peripheralServerMode).toStrictEqual(false)
    expect(ro.peripheralServerModeUuid).toBeUndefined()
    expect(ro.peripheralServerModeDeviceAddress).toBeUndefined()
  })
})
