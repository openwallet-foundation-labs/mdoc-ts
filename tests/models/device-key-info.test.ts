import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceKey } from '../../src/mdoc/models/device-key'
import { DeviceKeyInfo } from '../../src/mdoc/models/device-key-info'

const cbor =
  'a1696465766963654b6579a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67'

describe('device key info', () => {
  test('parse', () => {
    const deviceKeyInfo = DeviceKeyInfo.decode(hex.decode(cbor))

    expect(deviceKeyInfo.keyInfo).toBeUndefined()
    expect(deviceKeyInfo.keyAuthorizations).toBeUndefined()
    expect(deviceKeyInfo.deviceKey).toBeInstanceOf(DeviceKey)
  })
})
