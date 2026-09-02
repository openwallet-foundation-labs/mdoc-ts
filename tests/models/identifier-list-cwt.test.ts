import {
  ProtectedHeaders,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
  TypedMap,
  UnprotectedHeaders,
} from '@owf/cose'
import { StatusListCwtClaimKey } from '@owf/token-status-list'
import { describe, expect, it } from 'vitest'
import {
  IdentifierList,
  IdentifierListCwt,
  IdentifierListCwtPayload,
  IdentifierListCwtProtectedHeaders,
  MediaTypes,
} from '../../src'

const identifier = new Uint8Array([1, 2, 3, 4])
const notRevoked = new Uint8Array([9, 9])
const uri = 'https://example/identifierlists/1'

// `null` omits the header entirely; `undefined` (or absent) uses the conformant default.
const identifierListToken = ({
  typ = MediaTypes.IdentifierListCwt,
  algorithm = SignatureAlgorithm.ES256,
  subject = uri,
  issuedAt,
  expirationTime = new Date(Date.now() + 60_000),
}: {
  typ?: string | null
  algorithm?: SignatureAlgorithm | null
  subject?: string
  issuedAt?: Date
  expirationTime?: Date
} = {}) => {
  const headers = new Map<number, unknown>()
  if (algorithm !== null) {
    headers.set(RegisteredCwtHeaderClaimKey.Algorithm, algorithm)
  }
  if (typ !== null) {
    headers.set(RegisteredCwtHeaderClaimKey.Typ, typ)
  }

  const payload = IdentifierListCwtPayload.create({
    identifierList: IdentifierList.create({ identifiers: [identifier] }),
    uri: subject,
    issuedAt,
    expirationTime,
  })

  // Built through `Sign1` rather than `IdentifierListCwt.signAndEncode`, so that a token carrying
  // headers the identifier list schema rejects can be produced at all.
  return Sign1.fromDecodedStructure({
    protectedHeaders: ProtectedHeaders.create({ protectedHeaders: headers }),
    unprotectedHeaders: UnprotectedHeaders.create({ unprotectedHeaders: new Map() }),
    payload: payload.encode(),
    signature: new Uint8Array(64),
  }).encode()
}

describe('identifier list cwt', () => {
  it('decodes a cwt carrying typ in the protected header', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken())

    expect(cwt.typ).toStrictEqual(MediaTypes.IdentifierListCwt)
    expect(cwt.protectedHeaders).toBeInstanceOf(IdentifierListCwtProtectedHeaders)
    expect(cwt.algorithm).toStrictEqual(SignatureAlgorithm.ES256)
    expect(cwt.payload.subject).toStrictEqual(uri)
    expect(cwt.includes(identifier)).toStrictEqual(true)
    expect(cwt.includes(notRevoked)).toStrictEqual(false)
  })

  it('rejects a cwt that omits typ', () => {
    expect(() => IdentifierListCwt.fromToken(identifierListToken({ typ: null }))).toThrow(
      "Expected key 'Typ (16)' to be defined"
    )
  })

  it('rejects a cwt whose typ is for another media type', () => {
    expect(() => IdentifierListCwt.fromToken(identifierListToken({ typ: 'application/statuslist+cwt' }))).toThrow(
      "Typ (protected header 16) shall be 'application/identifierlist+cwt'"
    )
  })

  // § 12.3.6.3 restricts what a list is *signed* with, but decoding stays permissive so an
  // algorithm outside the profile — a fully-specified alias such as ESP256 (-9), say — is
  // judged on whether its signature verifies, as it is for reader authentication.
  it('decodes a cwt signed with an algorithm outside the profile', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ algorithm: SignatureAlgorithm.RS256 }))

    expect(cwt.algorithm).toStrictEqual(SignatureAlgorithm.RS256)
  })

  it('decodes a cwt without an algorithm', () => {
    expect(IdentifierListCwt.fromToken(identifierListToken({ algorithm: null })).algorithm).toBeUndefined()
  })

  it('defaults typ to the identifier list media type when constructed', () => {
    const cwt = new IdentifierListCwt({
      payload: {
        identifierList: IdentifierList.create({ identifiers: [identifier] }),
        uri,
        expirationTime: new Date(Date.now() + 60_000),
      },
      protectedHeaders: new Map<number, unknown>([[RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256]]),
    })

    expect(cwt.typ).toStrictEqual(MediaTypes.IdentifierListCwt)
  })
})

describe('identifier list cwt verifyStatus', () => {
  it('passes for an identifier that is not on the list', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken())

    expect(() => cwt.verifyStatus(notRevoked)).not.toThrow()
  })

  it('throws when the identifier is on the list', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken())

    expect(() => cwt.verifyStatus(identifier)).toThrow(
      `Identifier 01020304 found in the revoked identifier list at '${uri}'`
    )
  })
})

describe('identifier list cwt verifyClaims', () => {
  // Token Status List: sub shall equal the uri the list was referenced by.
  it('throws when the subject does not match the uri it was fetched from', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ subject: 'https://example/identifierlists/2' }))

    expect(() => cwt.verifyClaims({ uri })).toThrow(
      "The 'Subject (2)' claim 'https://example/identifierlists/2' does not match the expected value"
    )
  })

  it('throws when the list is expired', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ expirationTime: new Date(Date.now() - 60_000) }))

    expect(() => cwt.verifyClaims({ uri })).toThrow('is in the past')
  })

  it('throws when the list is issued in the future', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ issuedAt: new Date(Date.now() + 60_000) }))

    expect(() => cwt.verifyClaims({ uri })).toThrow('is in the future')
  })

  it('accepts a list that expired within the allowed skew, and rejects it once narrowed', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ expirationTime: new Date(Date.now() - 10_000) }))

    expect(() => cwt.verifyClaims({ uri })).not.toThrow()
    expect(() => cwt.verifyClaims({ uri, skewSeconds: 1 })).toThrow('is in the past')
  })

  it('does not check the issuance time when freshness checking is disabled', () => {
    const cwt = IdentifierListCwt.fromToken(identifierListToken({ issuedAt: new Date(Date.now() + 60_000) }))

    expect(() => cwt.verifyClaims({ uri, checkIssuedAt: false })).not.toThrow()
  })
})

describe('identifier list cwt payload', () => {
  const payload = () =>
    IdentifierListCwtPayload.create({
      identifierList: IdentifierList.create({ identifiers: [] }),
      uri,
      expirationTime: new Date(Date.now() + 60_000),
    }).encodedStructure as unknown as Map<unknown, unknown>

  // § 12.3.6.3 defers to Token Status List, where sub and iat are REQUIRED.
  it('rejects a payload without a subject', () => {
    const encoded = payload()
    encoded.delete(RegisteredCwtClaimKey.Subject)

    expect(() => IdentifierListCwtPayload.fromEncodedStructure(encoded as never)).toThrow(
      "Expected key 'Subject (2)' to be defined"
    )
  })

  // § 12.3.6.3: "The exp claim shall be present."
  it('rejects a payload without an expiration', () => {
    const encoded = payload()
    encoded.delete(RegisteredCwtClaimKey.ExpirationTime)

    expect(() => IdentifierListCwtPayload.fromEncodedStructure(encoded as never)).toThrow(
      "Expected key 'ExpirationTime (4)' to be defined"
    )
  })

  // § 12.3.6.4: "The StatusList claim shall not be present in the CWT claims set."
  it('rejects a payload that also carries a status list claim', () => {
    const encoded = payload()
    encoded.set(StatusListCwtClaimKey.StatusList, new Map())

    expect(() => IdentifierListCwtPayload.fromEncodedStructure(encoded as never)).toThrow(
      'The StatusList claim (65533) shall not be present in an identifier list CWT'
    )
  })
})

describe('identifier list cwt protected headers', () => {
  const headers = (x5chain: unknown) =>
    IdentifierListCwtProtectedHeaders.fromDecodedStructure(
      TypedMap.fromMap(
        new Map<number, unknown>([
          [RegisteredCwtHeaderClaimKey.Typ, MediaTypes.IdentifierListCwt],
          [RegisteredCwtHeaderClaimKey.Algorithm, SignatureAlgorithm.ES256],
          [RegisteredCwtHeaderClaimKey.X5Chain, x5chain],
        ])
      )
    )

  it('normalizes a single-certificate x5chain to an array', () => {
    const certificate = new Uint8Array([9, 9, 9])

    expect(headers(certificate).x5chain).toStrictEqual([certificate])
  })

  it('rejects an x5chain that is not made up of byte strings', () => {
    expect(() => headers(['not-a-certificate'])).toThrow()
  })
})
