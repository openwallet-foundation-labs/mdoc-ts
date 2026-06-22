import { describe, expect, test } from 'vitest'
import type { MdocContext } from '../../src'
import { randomUnsignedInteger } from '../../src/utils/randomUnsignedInteger'
import { mdocContext } from '../context'

const MAX_DIGEST_ID = 2 ** 31 - 1

/**
 * Build a context whose `crypto.random` returns the given fixed bytes, so we
 * can drive `randomUnsignedInteger` deterministically.
 */
const contextWithBytes = (bytes: number[]): Pick<MdocContext, 'crypto'> => ({
  crypto: {
    ...mdocContext.crypto,
    random: () => new Uint8Array(bytes),
  },
})

describe('randomUnsignedInteger', () => {
  test('all bits set stays within the ISO 18013-5 §12.3.4 range (2^31 - 1)', () => {
    // With `>>> 0` this would have returned 4294967295 (2^32 - 1), which is
    // larger than 2^31 and therefore not spec-compliant.
    expect(randomUnsignedInteger(contextWithBytes([0xff, 0xff, 0xff, 0xff]))).toBe(MAX_DIGEST_ID)
  })

  test('most significant bit is cleared while lower bits are preserved', () => {
    // 0x80000001 -> high bit dropped -> 0x00000001
    expect(randomUnsignedInteger(contextWithBytes([0x80, 0x00, 0x00, 0x01]))).toBe(1)
    // 0xFFFFFFFE -> high bit dropped -> 0x7FFFFFFE
    expect(randomUnsignedInteger(contextWithBytes([0xff, 0xff, 0xff, 0xfe]))).toBe(MAX_DIGEST_ID - 1)
  })

  test('all zero bytes produce zero', () => {
    expect(randomUnsignedInteger(contextWithBytes([0x00, 0x00, 0x00, 0x00]))).toBe(0)
  })

  test('value below the high bit is returned unchanged', () => {
    // 0x12345678 has the high bit unset, so masking is a no-op.
    expect(randomUnsignedInteger(contextWithBytes([0x12, 0x34, 0x56, 0x78]))).toBe(0x12345678)
  })

  test('many invocations with real randomness stay within range', () => {
    for (let i = 0; i < 10_000; i++) {
      const value = randomUnsignedInteger(mdocContext)
      expect(Number.isInteger(value)).toBe(true)
      expect(value).toBeGreaterThanOrEqual(0)
      expect(value).toBeLessThanOrEqual(MAX_DIGEST_ID)
    }
  })
})
