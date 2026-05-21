import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { EDeviceKey } from '../../src/mdoc/models/e-device-key'
import { Security } from '../../src/mdoc/models/security'

const cbor =
  '8201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67'

describe('security', () => {
  test('parse', () => {
    const security = Security.decode(hex.decode(cbor))

    expect(security.cipherSuiteIdentifier).toStrictEqual(1)
    expect(security.eDeviceKey).toBeInstanceOf(EDeviceKey)
  })
})
