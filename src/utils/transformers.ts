import z from 'zod'

const base64ToBytes = z.codec(z.base64(), z.instanceof(Uint8Array), {
  decode: (base64String) => z.util.base64ToUint8Array(base64String),
  encode: (bytes) => z.util.uint8ArrayToBase64(bytes),
})

const base64urlToBytes = z.codec(z.base64url(), z.instanceof(Uint8Array), {
  decode: (base64urlString) => z.util.base64urlToUint8Array(base64urlString),
  encode: (bytes) => z.util.uint8ArrayToBase64url(bytes),
})

const hexToBytes = z.codec(z.hex(), z.instanceof(Uint8Array), {
  decode: (hexString) => z.util.hexToUint8Array(hexString),
  encode: (bytes) => z.util.uint8ArrayToHex(bytes),
})

const bytesToUtf8 = z.codec(z.instanceof(Uint8Array), z.string(), {
  decode: (bytes) => new TextDecoder().decode(bytes),
  encode: (str) => new TextEncoder().encode(str),
})

export const base64 = {
  decode: (data: string) => base64ToBytes.decode(data),
  encode: (data: Uint8Array) => base64ToBytes.encode(data as Uint8Array<ArrayBuffer>),
}

export const base64url = {
  decode: (data: string) => base64urlToBytes.decode(data),
  encode: (data: Uint8Array) => base64urlToBytes.encode(data as Uint8Array<ArrayBuffer>),
}

export const hex = {
  decode: (data: string) => hexToBytes.decode(data),
  encode: (data: Uint8Array) => hexToBytes.encode(data as Uint8Array<ArrayBuffer>),
}

export const stringToBytes = (data: string) => bytesToUtf8.encode(data)
export const bytesToString = (data: Uint8Array) => bytesToUtf8.decode(data as Uint8Array<ArrayBuffer>)

export const concatBytes = (byteArrays: Array<Uint8Array>): Uint8Array => {
  const totalLength = byteArrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of byteArrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

export const compareBytes = (lhs: Uint8Array, rhs: Uint8Array) => {
  if (lhs === rhs) return true
  if (lhs.byteLength !== rhs.byteLength) return false
  return lhs.every((b, i) => b === rhs[i])
}
