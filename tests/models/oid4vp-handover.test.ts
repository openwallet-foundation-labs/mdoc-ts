import { hex } from '@owf/identity-common'
import { expect, suite, test } from 'vitest'
import { Oid4vpHandover } from '../../src/mdoc/models/oid4vp-handover'

const cbor =
  '82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac'

suite('oid4vp handover', () => {
  test('parse', () => {
    const oid4vpHandover = Oid4vpHandover.decode(hex.decode(cbor))

    expect(oid4vpHandover.handoverInfoHash).toBeDefined()
  })

  test('construct', () => {
    const oid4vpHandover = Oid4vpHandover.createFromHash(
      new Uint8Array([
        4, 139, 192, 83, 192, 4, 66, 175, 155, 142, 237, 73, 76, 239, 221, 157, 149, 36, 13, 37, 75, 4, 107, 17, 182,
        128, 19, 114, 42, 173, 56, 172,
      ])
    )

    expect(hex.encode(oid4vpHandover.encode())).toStrictEqual(cbor)
  })
})
