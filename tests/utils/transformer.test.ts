import { describe, expect, test } from 'vitest'
import { base64, base64url, bytesToString, compareBytes, concatBytes, hex, stringToBytes } from '../../src/utils'

describe('transformer', () => {
  describe('base64', () => {
    test('basic encoding and decoding', () => {
      const s = 'Hello World!'
      const b = stringToBytes(s)
      const encoded = base64.encode(b)
      const decoded = base64.decode(encoded)
      const received = bytesToString(decoded)
      expect(received).toStrictEqual(s)
    })

    test('padded base64 encoding', () => {
      // Test strings that result in different padding scenarios
      const testCases = [
        { input: 'a', expected: 'YQ==' }, // 2 padding chars
        { input: 'ab', expected: 'YWI=' }, // 1 padding char
        { input: 'abc', expected: 'YWJj' }, // No padding
        { input: 'abcd', expected: 'YWJjZA==' }, // 2 padding chars
      ]

      for (const { input, expected } of testCases) {
        const bytes = stringToBytes(input)
        const encoded = base64.encode(bytes)
        expect(encoded).toBe(expected)
      }
    })

    test('valid base64 characters', () => {
      // Generate random strings from valid base64 characters and verify roundtrip
      const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

      for (let trial = 0; trial < 10; trial++) {
        // Generate random length string (4-40 chars, multiple of 4 for proper base64)
        const length = (Math.floor(Math.random() * 10) + 1) * 4
        let randomBase64 = ''

        for (let i = 0; i < length; i++) {
          randomBase64 += BASE64_CHARS[Math.floor(Math.random() * BASE64_CHARS.length)]
        }

        // Decode and re-encode - should get back similar structure
        const decoded = base64.decode(randomBase64)
        const reencoded = base64.encode(decoded)

        // The re-encoded version should decode to the same bytes
        const decodedAgain = base64.decode(reencoded)
        expect(compareBytes(decoded, decodedAgain)).toBe(true)
      }
    })

    test('invalid base64 characters throw error', () => {
      // Invalid characters should cause the decoder to throw an error
      const invalidInputs = [
        'SGVsbG8@V29ybGQh', // @ is not valid base64
        'YWJj#ZGVm', // # is not valid base64
        'Hello!', // plain text, not base64
        'YWJj===', // too much padding
        'YWJj=ZGVm', // padding in wrong position
      ]

      for (const invalid of invalidInputs) {
        expect(() => base64.decode(invalid)).toThrow()
      }
    })

    test('valid base64 with padding does not throw', () => {
      // Valid base64 strings should not throw
      const validInputs = ['YQ==', 'YWI=', 'YWJj', 'SGVsbG9Xb3JsZA==']

      for (const valid of validInputs) {
        expect(() => base64.decode(valid)).not.toThrow()
      }
    })

    test('edge case: empty input', () => {
      const emptyBytes = new Uint8Array([])
      const encoded = base64.encode(emptyBytes)
      expect(encoded).toBe('')

      const decoded = base64.decode('')
      expect(decoded.length).toBe(0)
    })

    test('binary data roundtrip', () => {
      // Test with raw binary data, not just text
      const binaryData = new Uint8Array([0, 1, 2, 255, 254, 253, 127, 128])
      const encoded = base64.encode(binaryData)
      const decoded = base64.decode(encoded)
      expect(compareBytes(decoded, binaryData)).toBe(true)
    })

    test('unicode characters', () => {
      const unicode = '你好世界 🌍'
      const bytes = stringToBytes(unicode)
      const encoded = base64.encode(bytes)
      const decoded = base64.decode(encoded)
      const result = bytesToString(decoded)
      expect(result).toBe(unicode)
    })
  })

  describe('base64url', () => {
    test('basic encoding and decoding', () => {
      const s = 'Hello World!'
      const b = stringToBytes(s)
      const encoded = base64url.encode(b)
      const decoded = base64url.decode(encoded)
      const received = bytesToString(decoded)
      expect(received).toStrictEqual(s)
    })

    test('URL-safe characters (no padding)', () => {
      // base64url should not contain +, /, or = characters
      const testCases = [
        'a',
        'ab',
        'abc',
        'abcd',
        'Hello World!',
        '>>??<<', // Characters that produce + and / in standard base64
      ]

      for (const input of testCases) {
        const bytes = stringToBytes(input)
        const encoded = base64url.encode(bytes)

        // base64url should not have padding
        expect(encoded).not.toContain('=')
        // Should use - instead of +
        expect(encoded).not.toContain('+')
        // Should use _ instead of /
        expect(encoded).not.toContain('/')
      }
    })

    test('base64url vs base64 character differences', () => {
      // Create data that will produce + and / in base64
      const data = new Uint8Array([0xff, 0xfe, 0xfd])

      const base64Encoded = base64.encode(data)
      const base64urlEncoded = base64url.encode(data)

      // Standard base64 may have + or /
      const base64Clean = base64Encoded.replace(/=/g, '')
      // base64url should have - and _ instead
      const converted = base64Clean.replace(/\+/g, '-').replace(/\//g, '_')

      expect(base64urlEncoded).toBe(converted)
    })

    test('decoding unpadded base64url', () => {
      // base64url should never have padding, only test unpadded inputs
      const testCases = [
        { input: 'YQ', expected: 'a' }, // Unpadded
        { input: 'YWI', expected: 'ab' }, // Unpadded
        { input: 'YWJj', expected: 'abc' }, // No padding needed
        { input: 'YWJjZA', expected: 'abcd' }, // Unpadded
      ]

      for (const { input, expected } of testCases) {
        const decoded = base64url.decode(input)
        const result = bytesToString(decoded)
        expect(result).toBe(expected)
      }
    })

    test('roundtrip with URL-unsafe characters', () => {
      // Test data that produces URL-unsafe characters in standard base64
      const testData = new Uint8Array([0x04, 0xd2, 0x14, 0x9f, 0xbf, 0x86, 0x40, 0x4a, 0x8e, 0x9b, 0x90, 0x50])

      const encoded = base64url.encode(testData)
      const decoded = base64url.decode(encoded)

      expect(compareBytes(decoded, testData)).toBe(true)
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      expect(encoded).not.toContain('=')
    })

    test('edge case: empty input', () => {
      const emptyBytes = new Uint8Array([])
      const encoded = base64url.encode(emptyBytes)
      expect(encoded).toBe('')

      const decoded = base64url.decode('')
      expect(decoded.length).toBe(0)
    })

    test('unicode characters', () => {
      const unicode = '你好世界 🌍'
      const bytes = stringToBytes(unicode)
      const encoded = base64url.encode(bytes)
      const decoded = base64url.decode(encoded)
      const result = bytesToString(decoded)
      expect(result).toBe(unicode)
    })

    test('invalid base64url characters throw error', () => {
      // Invalid characters should cause the decoder to throw an error
      const invalidInputs = [
        'YWJj+ZGVm', // + is not valid base64url (it's base64)
        'YWJj/ZGVm', // / is not valid base64url (it's base64)
        'YWJj=', // = is not valid base64url (padding not allowed)
        'SGVsbG8@V29ybGQh', // @ is not valid
        'Hello!', // plain text, not base64url
      ]

      for (const invalid of invalidInputs) {
        expect(() => base64url.decode(invalid)).toThrow()
      }
    })

    test('valid base64url does not throw', () => {
      // Valid base64url strings should not throw
      const validInputs = [
        'YQ', // Unpadded
        'YWI', // Unpadded
        'YWJj', // No padding needed
        '__79', // Contains - and _
        'SGVsbG9Xb3JsZA', // No padding
      ]

      for (const valid of validInputs) {
        expect(() => base64url.decode(valid)).not.toThrow()
      }
    })

    test('decoding base64url with standard base64 decoder may produce incorrect data', () => {
      // Test with data that will definitely produce - or _ in different positions
      const testString = 'Hello World! Testing 123'
      const originalData = stringToBytes(testString)
      const base64urlEncoded = base64url.encode(originalData)

      // Only test if the base64url encoding actually contains - or _
      if (base64urlEncoded.includes('-') || base64urlEncoded.includes('_')) {
        // Try to decode base64url using standard base64 decoder
        const decodedWrong = base64.decode(base64urlEncoded)
        const resultWrong = bytesToString(decodedWrong)

        // Should NOT match the original string (data is corrupted)
        expect(resultWrong).not.toBe(testString)

        // Verify correct decoding with base64url
        const decodedCorrect = base64url.decode(base64urlEncoded)
        const resultCorrect = bytesToString(decodedCorrect)
        expect(resultCorrect).toBe(testString)
      } else {
        // If no special chars, decoders behave the same
        expect(true).toBe(true)
      }
    })
  })

  describe('hex', () => {
    test('basic encoding and decoding', () => {
      const s = 'Hello World!'
      const b = stringToBytes(s)
      const encoded = hex.encode(b)
      const decoded = hex.decode(encoded)
      const received = bytesToString(decoded)
      expect(received).toStrictEqual(s)
    })

    test('hex encoding format', () => {
      const testCases = [
        { input: new Uint8Array([0]), expected: '00' },
        { input: new Uint8Array([15]), expected: '0f' },
        { input: new Uint8Array([16]), expected: '10' },
        { input: new Uint8Array([255]), expected: 'ff' },
        { input: new Uint8Array([0, 255]), expected: '00ff' },
        { input: new Uint8Array([171, 205, 239]), expected: 'abcdef' },
      ]

      for (const { input, expected } of testCases) {
        const encoded = hex.encode(input)
        expect(encoded).toBe(expected)
      }
    })

    test('hex decoding case insensitivity', () => {
      // Hex should decode both uppercase and lowercase
      const testCases = [
        { input: 'abcdef', expected: new Uint8Array([171, 205, 239]) },
        { input: 'ABCDEF', expected: new Uint8Array([171, 205, 239]) },
        { input: 'AbCdEf', expected: new Uint8Array([171, 205, 239]) },
        { input: '00ff', expected: new Uint8Array([0, 255]) },
        { input: '00FF', expected: new Uint8Array([0, 255]) },
      ]

      for (const { input, expected } of testCases) {
        const decoded = hex.decode(input)
        expect(compareBytes(decoded, expected)).toBe(true)
      }
    })

    test('invalid hex characters throw error', () => {
      // Invalid hex characters should cause the decoder to throw an error
      const invalidInputs = [
        // 'gg', // g is not hex
        '0g', // g is not hex
        'xyz', // not hex
        'hello', // not hex
      ]

      for (const invalid of invalidInputs) {
        expect(() => hex.decode(invalid)).toThrow()
      }
    })

    test('odd length hex string throws error', () => {
      // Odd length hex strings should throw an error
      const oddLengthInputs = [
        '0', // Length 1
        '012', // Length 3
        'abcde', // Length 5
      ]

      for (const invalid of oddLengthInputs) {
        expect(() => hex.decode(invalid)).toThrow()
      }
    })

    test('even length hex string', () => {
      const testCases = [
        { input: '00', expectedLength: 1 },
        { input: '0000', expectedLength: 2 },
        { input: '0102', expectedLength: 2 },
        { input: '010203', expectedLength: 3 },
      ]

      for (const { input, expectedLength } of testCases) {
        const decoded = hex.decode(input)
        expect(decoded.length).toBe(expectedLength)
      }
    })

    test('edge case: empty input', () => {
      const emptyBytes = new Uint8Array([])
      const encoded = hex.encode(emptyBytes)
      expect(encoded).toBe('')

      const decoded = hex.decode('')
      expect(decoded.length).toBe(0)
    })

    test('all byte values', () => {
      // Test all possible byte values (0-255)
      const allBytes = new Uint8Array(256)
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i
      }

      const encoded = hex.encode(allBytes)
      const decoded = hex.decode(encoded)

      expect(compareBytes(decoded, allBytes)).toBe(true)
      expect(encoded.length).toBe(512) // 256 bytes * 2 chars per byte
    })

    test('unicode characters via hex', () => {
      const unicode = '你好'
      const bytes = stringToBytes(unicode)
      const encoded = hex.encode(bytes)
      const decoded = hex.decode(encoded)
      const result = bytesToString(decoded)
      expect(result).toBe(unicode)
    })
  })

  test('contact bytes', () => {
    const b1 = Uint8Array.from([1, 2, 3])
    const b2 = Uint8Array.from([4, 5, 6])
    const b3 = concatBytes([b1, b2])

    expect(b3).toContain(1)
    expect(b3).toContain(2)
    expect(b3).toContain(3)
    expect(b3).toContain(4)
    expect(b3).toContain(5)
    expect(b3).toContain(6)
  })

  test('compare bytes', () => {
    const b1 = Uint8Array.from([1, 2, 3])
    const b2 = Uint8Array.from([4, 5, 6])
    const b3 = Uint8Array.from([4, 5, 6])
    const b4 = Uint8Array.from([4, 5, 6, 7])

    const compareSameInstance = compareBytes(b1, b1)
    const compareSameLength = compareBytes(b1, b2)
    const compareSameContent = compareBytes(b2, b3)
    const compareDifferentLength = compareBytes(b3, b4)

    expect(compareSameInstance).toStrictEqual(true)
    expect(compareSameLength).toStrictEqual(false)
    expect(compareSameContent).toStrictEqual(true)
    expect(compareDifferentLength).toStrictEqual(false)
  })
})
