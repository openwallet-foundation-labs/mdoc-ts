import { describe, expect, test } from 'vitest'
import { DeviceMac, hex, RegisteredCwtHeaderClaimKey } from '../../src'

const cbor = '8443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d'

describe('device mac', () => {
  test('parse', () => {
    const deviceMac = DeviceMac.decode(hex.decode(cbor))

    expect(deviceMac.payload).toBeNull()
    expect(deviceMac.tag).toBeDefined()
    expect(deviceMac.protectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.Algorithm)).toBeTruthy()
  })
})
