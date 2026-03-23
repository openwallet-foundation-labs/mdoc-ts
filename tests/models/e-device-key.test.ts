import { describe, expect, test } from 'vitest'
import { Curve, EDeviceKey, KeyType } from '../../src'
import { hex } from '../../src/utils'

const cbor =
  'a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67'

describe('e device key', () => {
  test('parse P-256', () => {
    const eDeviceKey = EDeviceKey.decode(hex.decode(cbor))

    expect(eDeviceKey.keyType).toStrictEqual(KeyType.Ec)
    expect(eDeviceKey.curve).toStrictEqual(Curve['P-256'])
    expect(eDeviceKey.x).toBeDefined()
    expect(eDeviceKey.y).toBeDefined()
  })

  test('parse ed25519', () => {
    const jwk = {
      crv: 'Ed25519',
      x: 'WCv8ZVRzdohwNDKODbeOZ_Plety0GMYHHZJD6jTswN0',
      kty: 'OKP',
      kid: '3fd4cea1-38e8-47f3-a5e5-9c0ea7303853',
    }

    const deviceKey = EDeviceKey.fromJwk(jwk)

    expect(deviceKey.keyType).toStrictEqual(KeyType.Okp)
    expect(deviceKey.curve).toStrictEqual(Curve.Ed25519)
    expect(deviceKey.x).toBeDefined()
    expect(deviceKey.y).not.toBeDefined()
  })
})
