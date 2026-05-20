import { describe, expect, test } from 'vitest'
import { cborDecode, cborEncode, DataItem } from '../../src/cbor'
import { IdentifierListInfo } from '../../src/mdoc/models/identifier-list-info'
import { Status } from '../../src/mdoc/models/status'
import { StatusListInfo } from '../../src/mdoc/models/status-list-info'

describe('StatusListInfo', () => {
  test('round-trip uri + idx', () => {
    const original = StatusListInfo.create({ uri: 'https://issuer.example/status/1', idx: 42 })
    const decoded = StatusListInfo.decode(original.encode())
    expect(decoded.uri).toBe('https://issuer.example/status/1')
    expect(decoded.idx).toBe(42)
    expect(decoded.certificate).toBeUndefined()
  })

  test('round-trip with certificate', () => {
    const cert = new Uint8Array([0x30, 0x82, 0x01, 0x00])
    const original = StatusListInfo.create({ uri: 'https://example/list', idx: 0, certificate: cert })
    const decoded = StatusListInfo.decode(original.encode())
    expect(decoded.certificate).toEqual(cert)
  })

  test('preserves unknown RFU keys', () => {
    // Spec allows `* tstr => RFU` — verify decode + encode keeps unknown keys.
    const raw = new Map<string, unknown>([
      ['uri', 'https://example/list'],
      ['idx', 7],
      ['vendor_ext', 'custom'],
    ])
    const decoded = StatusListInfo.decode(cborEncode(raw))
    expect(decoded.uri).toBe('https://example/list')
    expect(decoded.idx).toBe(7)

    const reEncoded = decoded.encode()
    const reDecoded = cborDecode(reEncoded, { unwrapTopLevelDataItem: false }) as DataItem | Map<unknown, unknown>
    const map = reDecoded instanceof DataItem ? (reDecoded.data as Map<unknown, unknown>) : reDecoded
    expect(map.get('vendor_ext')).toBe('custom')
  })
})

describe('IdentifierListInfo', () => {
  test('round-trip id + uri', () => {
    const id = new Uint8Array([1, 2, 3, 4])
    const original = IdentifierListInfo.create({ id, uri: 'https://example/identifiers' })
    const decoded = IdentifierListInfo.decode(original.encode())
    expect(decoded.id).toEqual(id)
    expect(decoded.uri).toBe('https://example/identifiers')
    expect(decoded.certificate).toBeUndefined()
  })

  test('round-trip with certificate', () => {
    const cert = new Uint8Array([0x30, 0x82, 0x02, 0x00])
    const original = IdentifierListInfo.create({
      id: new Uint8Array([0xaa]),
      uri: 'https://example/identifiers',
      certificate: cert,
    })
    const decoded = IdentifierListInfo.decode(original.encode())
    expect(decoded.certificate).toEqual(cert)
  })

  test('preserves unknown RFU keys', () => {
    const raw = new Map<string, unknown>([
      ['id', new Uint8Array([0xff])],
      ['uri', 'https://example/identifiers'],
      ['ecosystem_tag', 42],
    ])
    const decoded = IdentifierListInfo.decode(cborEncode(raw))
    expect(decoded.uri).toBe('https://example/identifiers')

    const reEncoded = decoded.encode()
    const reDecoded = cborDecode(reEncoded, { unwrapTopLevelDataItem: false }) as DataItem | Map<unknown, unknown>
    const map = reDecoded instanceof DataItem ? (reDecoded.data as Map<unknown, unknown>) : reDecoded
    expect(map.get('ecosystem_tag')).toBe(42)
  })
})

describe('Status', () => {
  test('round-trip with neither status_list nor identifier_list (extension-only)', () => {
    // Spec allows Status to be present with only RFU keys.
    const raw = new Map<string, unknown>([['custom_ext', 'value']])
    const decoded = Status.decode(cborEncode(raw))
    expect(decoded.statusList).toBeUndefined()
    expect(decoded.identifierList).toBeUndefined()

    const reEncoded = decoded.encode()
    const reDecoded = cborDecode(reEncoded, { unwrapTopLevelDataItem: false }) as DataItem | Map<unknown, unknown>
    const map = reDecoded instanceof DataItem ? (reDecoded.data as Map<unknown, unknown>) : reDecoded
    expect(map.get('custom_ext')).toBe('value')
  })

  test('preserves unknown RFU keys alongside known fields', () => {
    const raw = new Map<string, unknown>([
      [
        'status_list',
        new Map<string, unknown>([
          ['uri', 'https://example/list'],
          ['idx', 9],
        ]),
      ],
      ['rfu_field', 'reserved'],
    ])
    const decoded = Status.decode(cborEncode(raw))
    expect(decoded.statusList?.idx).toBe(9)

    const reEncoded = decoded.encode()
    const reDecoded = cborDecode(reEncoded, { unwrapTopLevelDataItem: false }) as DataItem | Map<unknown, unknown>
    const map = reDecoded instanceof DataItem ? (reDecoded.data as Map<unknown, unknown>) : reDecoded
    expect(map.get('rfu_field')).toBe('reserved')
    // Known field should also still be present.
    expect((map.get('status_list') as Map<string, unknown>).get('idx')).toBe(9)
  })

  test('empty Status round-trips', () => {
    const original = Status.create({})
    const decoded = Status.decode(original.encode())
    expect(decoded.statusList).toBeUndefined()
    expect(decoded.identifierList).toBeUndefined()
  })
})
