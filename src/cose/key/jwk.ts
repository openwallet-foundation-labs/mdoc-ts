import { base64url } from '../../utils'
import { EncryptionAlgorithm, MacAlgorithm, SignatureAlgorithm } from '../headers/defaults'
import { Curve } from './curve'
import type { CoseKeyOptions } from './key'
import { KeyOps } from './key-operation'
import { KeyType } from './key-type'

const swapMap = (map: Record<string, string>) =>
  Object.fromEntries(Object.entries(map).map(([key, value]) => [value, key]))

const swapNestedMap = (nestedMap: Record<string, Record<string, unknown>>) =>
  Object.fromEntries(
    Object.entries(nestedMap).map(([category, mappings]) => [
      category,
      Object.fromEntries(Object.entries(mappings).map(([key, value]) => [value, key])),
    ])
  )

const jwkCoseKeyMap = {
  kty: {
    OKP: KeyType.Okp,
    EC: KeyType.Ec,
    OCT: KeyType.Oct,
  },
  crv: {
    'P-256': Curve['P-256'],
    'p-384': Curve['P-384'],
    'p-521': Curve['P-521'],
    X25519: Curve.X25519,
    Ed25519: Curve.Ed25519,
    Ed448: Curve.Ed448,
  },
  alg: {
    EdDSA: SignatureAlgorithm.EdDSA,
    ES256: SignatureAlgorithm.ES256,
    ES384: SignatureAlgorithm.ES384,
    ES512: SignatureAlgorithm.ES512,
    PS256: SignatureAlgorithm.PS256,
    PS384: SignatureAlgorithm.PS384,
    PS512: SignatureAlgorithm.PS512,
    RS256: SignatureAlgorithm.RS256,
    RS384: SignatureAlgorithm.RS384,
    RS512: SignatureAlgorithm.RS512,

    HS256: MacAlgorithm.HS256,
    HS384: MacAlgorithm.HS384,
    HS512: MacAlgorithm.HS512,

    A128GCM: EncryptionAlgorithm.A128GCM,
    A192GCM: EncryptionAlgorithm.A192GCM,
    A256GCM: EncryptionAlgorithm.A256GCM,
    Direct: EncryptionAlgorithm.Direct,
  },
  keyOps: {
    sign: KeyOps.Sign,
    verify: KeyOps.Verify,
    encrypt: KeyOps.Encrypt,
    decrypt: KeyOps.Decrypt,
    wrapKey: KeyOps.WrapKey,
    unwrapKey: KeyOps.UnwrapKey,
    deriveKey: KeyOps.DeriveKey,
    deriveBits: KeyOps.DeriveBits,
    mACCreate: KeyOps.MACCreate,
    mACVerify: KeyOps.MACVerify,
  },
}

const coseKeyJwkMap = swapNestedMap(jwkCoseKeyMap)

export const jwkCoseOptionsMap: Record<string, keyof CoseKeyOptions> = {
  kty: 'keyType',
  kid: 'keyId',
  alg: 'algorithm',
  keyOps: 'keyOps',
  baseIv: 'baseIv',
  crv: 'curve',
  x: 'x',
  y: 'y',
  d: 'd',
}

export const coseOptionsJwkMap = swapMap(jwkCoseOptionsMap)

export const jwkToCoseKey = {
  kty: (kty?: unknown) => {
    return jwkCoseKeyMap.kty[kty as keyof (typeof jwkCoseKeyMap)['kty']] ?? kty
  },
  crv: (crv?: unknown) => jwkCoseKeyMap.crv[crv as keyof (typeof jwkCoseKeyMap)['crv']] ?? crv,
  alg: (alg?: unknown) => jwkCoseKeyMap.alg[alg as keyof (typeof jwkCoseKeyMap)['alg']] ?? alg,
  kid: (kid?: unknown) => kid,
  keyOps: (keyOps?: unknown) =>
    Array.isArray(keyOps)
      ? keyOps?.map((ko) => jwkCoseKeyMap.keyOps[ko as keyof (typeof jwkCoseKeyMap)['keyOps']] ?? ko)
      : undefined,
  x: (s?: unknown) => (s && typeof s === 'string' ? base64url.decode(s) : undefined),
  y: (s?: unknown) => (s && typeof s === 'string' ? base64url.decode(s) : undefined),
  d: (s?: unknown) => (s && typeof s === 'string' ? base64url.decode(s) : undefined),
}

export const coseKeyToJwk = {
  keyType: (keyType: KeyType) => coseKeyJwkMap.kty[keyType],
  keyId: (keyId: unknown) => keyId,
  algorithm: (algorithm?: SignatureAlgorithm | MacAlgorithm) => (algorithm ? coseKeyJwkMap.alg[algorithm] : undefined),
  keyOps: (keyOps?: unknown) =>
    keyOps && Array.isArray(keyOps) ? keyOps.map((ko) => coseKeyJwkMap.keyOps[ko]) : undefined,
  baseIv: (baseIv?: unknown) => baseIv,
  curve: (curve?: Curve) => (curve ? coseKeyJwkMap.crv[curve] : undefined),
  x: (x?: Uint8Array) => (x ? base64url.encode(x) : undefined),
  y: (y?: Uint8Array) => (y ? base64url.encode(y) : undefined),
  d: (d?: Uint8Array) => (d ? base64url.encode(d) : undefined),
}
