import { cborEncode, DataItem } from '@owf/cose'
import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { type IssuerAuth, IssuerNamespaces, IssuerSignedItem } from '../../src'
import { mdocContext } from '../context'

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

function createNonCanonicalPlaceOfBirthItemBytes() {
  const random = new Uint8Array(32).fill(7)
  const nestedMap = concatBytes(
    Uint8Array.of(0xa2),
    cborText('country'),
    cborText('IT'),
    cborText('region'),
    cborText('Lazio')
  )

  return concatBytes(
    Uint8Array.of(0xa4),
    cborText('digestID'),
    Uint8Array.of(0x19, 0x00, 0x00), // uint 0 as 16-bit; this library re-encodes as 0x00
    cborText('random'),
    cborBstr(random),
    cborText('elementIdentifier'),
    cborText('place_of_birth'),
    cborText('elementValue'),
    nestedMap
  )
}

describe('IssuerSignedItem original bytes', () => {
  test('isValid hashes received tag-24 bytes, not a re-encode', async () => {
    const innerBytes = createNonCanonicalPlaceOfBirthItemBytes()
    const namespaces = IssuerNamespaces.fromEncodedStructure(
      new Map([['eu.europa.ec.eudi.pid.1', [DataItem.fromBuffer(innerBytes)]]])
    )
    const item = namespaces.getIssuerNamespace('eu.europa.ec.eudi.pid.1')?.[0]
    if (!item) throw new Error('expected decoded issuer signed item')

    const receivedTaggedBytes = cborEncode(DataItem.fromBuffer(innerBytes))
    const fromOptionsEncoded = IssuerSignedItem.fromOptions({
      digestId: item.digestId,
      random: item.random,
      elementIdentifier: item.elementIdentifier,
      elementValue: item.elementValue,
    }).encode({ asDataItem: true })

    expect(hex.encode(fromOptionsEncoded)).not.toEqual(hex.encode(receivedTaggedBytes))
    expect(hex.encode(item.encode({ asDataItem: true }))).not.toEqual(hex.encode(receivedTaggedBytes))

    const digest = await mdocContext.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: receivedTaggedBytes,
    })

    const issuerAuth = {
      mobileSecurityObject: {
        digestAlgorithm: 'SHA-256',
        valueDigests: {
          valueDigests: new Map([['eu.europa.ec.eudi.pid.1', new Map([[0, digest]])]]),
        },
      },
    } as IssuerAuth

    await expect(item.isValid('eu.europa.ec.eudi.pid.1', issuerAuth, mdocContext)).resolves.toBe(true)
  })
})
