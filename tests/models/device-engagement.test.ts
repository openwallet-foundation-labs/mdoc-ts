import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { DeviceEngagement } from '../../src/mdoc/models/device-engagement'
import { Security } from '../../src/mdoc/models/security'

const cbor =
  'a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917'

describe('device engagement', () => {
  test('parse', () => {
    const deviceEngagement = DeviceEngagement.decode(hex.decode(cbor))

    expect(deviceEngagement.version).toStrictEqual('1.0')
    expect(deviceEngagement.security).toBeInstanceOf(Security)
    expect(deviceEngagement.deviceRetrievalMethods).toBeDefined()
  })
})
