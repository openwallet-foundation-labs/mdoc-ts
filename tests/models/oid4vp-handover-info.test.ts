import { hex } from '@owf/identity-common'
import { expect, suite, test } from 'vitest'
import { Oid4vpHandoverInfo } from '../../src/mdoc/models/oid4vp-handover-info'

const cbor =
  '847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365'

suite('oid4vp handover', () => {
  test('parse', () => {
    const oid4vpHandoverInfo = Oid4vpHandoverInfo.decode(hex.decode(cbor))

    expect(oid4vpHandoverInfo.clientId).toStrictEqual('x509_san_dns:example.com')
    expect(oid4vpHandoverInfo.nonce).toStrictEqual('exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA')

    expect(oid4vpHandoverInfo.jwkThumbprint).toStrictEqual(
      new Uint8Array([
        66, 131, 236, 146, 122, 224, 242, 8, 218, 170, 45, 2, 106, 129, 79, 43, 34, 220, 165, 44, 248, 95, 250, 143, 63,
        134, 38, 198, 189, 102, 144, 71,
      ])
    )
    expect(oid4vpHandoverInfo.responseUri).toStrictEqual('https://example.com/response')
  })

  test('construct', () => {
    const oid4vpHandoverInfo = Oid4vpHandoverInfo.create({
      clientId: 'x509_san_dns:example.com',
      nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
      jwkThumbprint: new Uint8Array([
        66, 131, 236, 146, 122, 224, 242, 8, 218, 170, 45, 2, 106, 129, 79, 43, 34, 220, 165, 44, 248, 95, 250, 143, 63,
        134, 38, 198, 189, 102, 144, 71,
      ]),
      responseUri: 'https://example.com/response',
    })

    expect(hex.encode(oid4vpHandoverInfo.encode())).toStrictEqual(cbor)
  })
})
