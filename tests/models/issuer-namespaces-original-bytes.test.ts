import { cborDecode, cborEncode, DataItem } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { IssuerNamespaces, IssuerSignedItem } from '../../src'

const NAMESPACE = 'eu.europa.ec.eudi.pid.1'

function concatBytes(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function cborText(value: string) {
  const encoded = new TextEncoder().encode(value)
  if (encoded.length >= 24) throw new Error(`text too long: ${value}`)
  return concatBytes(Uint8Array.of(0x60 + encoded.length), encoded)
}

function cborBstr(value: Uint8Array) {
  if (value.length >= 256) throw new Error('bstr too long')
  return concatBytes(Uint8Array.of(0x58, value.length), value)
}

/**
 * An `IssuerSignedItem` whose `digestID` is a 16-bit uint rather than the shortest form this
 * library would emit. Stands in for any issuer whose CBOR encoder is not deterministic.
 */
function issuerSignedItemBytes() {
  return concatBytes(
    Uint8Array.of(0xa4),
    cborText('digestID'),
    Uint8Array.of(0x19, 0x00, 0x00),
    cborText('random'),
    cborBstr(new Uint8Array(32).fill(7)),
    cborText('elementIdentifier'),
    cborText('given_name'),
    cborText('elementValue'),
    cborText('Alice')
  )
}

/** The `{<NAMESPACE>: [<item>]}` map as an issuer signed credential would carry it. */
function encodedNamespaces(payload: Uint8Array) {
  return cborEncode(new Map([[NAMESPACE, [DataItem.fromBuffer(payload)]]]))
}

function decodeNamespaces(payload: Uint8Array) {
  return IssuerNamespaces.fromEncodedStructure(
    cborDecode(encodedNamespaces(payload), { unwrapTopLevelDataItem: false })
  )
}

describe('IssuerNamespaces presentation encoding', () => {
  test('forwards the issuer bytes for items we received', () => {
    const payload = issuerSignedItemBytes()
    const item = decodeNamespaces(payload).getIssuerNamespace(NAMESPACE)?.[0]
    if (!item) throw new Error('expected a decoded issuer signed item')

    // Re-encoding from the decoded structure really does differ, so this is not vacuous:
    // digestID 0x19 0x00 0x00 collapses to 0x00 and the digest stops matching valueDigests.
    expect(hex.encode(item.encode({ asDataItem: true }))).not.toEqual(
      hex.encode(cborEncode(DataItem.fromBuffer(payload)))
    )

    const [, items] = [...decodeNamespaces(payload).encodedStructure.entries()][0]
    expect(hex.encode(items[0].buffer)).toEqual(hex.encode(payload))
  })

  test('a decoded credential round trips to the bytes it was decoded from', () => {
    const payload = issuerSignedItemBytes()

    expect(hex.encode(decodeNamespaces(payload).encode())).toEqual(hex.encode(encodedNamespaces(payload)))
  })

  test('disclosing a subset keeps each remaining item byte for byte', () => {
    const payload = issuerSignedItemBytes()
    const disclosed = decodeNamespaces(payload).getIssuerNamespace(NAMESPACE) ?? []

    // limitDisclosureToDeviceRequestNameSpaces builds the presented namespaces out of the
    // very same IssuerSignedItem instances, so the issuer bytes have to survive the rebuild.
    const namespaces = IssuerNamespaces.create({ issuerNamespaces: new Map([[NAMESPACE, disclosed]]) })

    expect(hex.encode(namespaces.encode())).toEqual(hex.encode(encodedNamespaces(payload)))
  })

  test('items we built ourselves still encode from their structure', () => {
    const item = IssuerSignedItem.fromOptions({
      digestId: 0,
      random: new Uint8Array(32).fill(7),
      elementIdentifier: 'given_name',
      elementValue: 'Alice',
    })

    expect(item.originalPayloadBytes).toBeUndefined()

    const namespaces = IssuerNamespaces.create({ issuerNamespaces: new Map([[NAMESPACE, [item]]]) })
    expect(hex.encode(namespaces.encode())).toEqual(
      hex.encode(cborEncode(new Map([[NAMESPACE, [DataItem.fromData(item.encodedStructure)]]])))
    )
  })
})
