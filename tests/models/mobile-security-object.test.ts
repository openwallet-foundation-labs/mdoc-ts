import { describe, expect, test } from 'vitest'
import { DeviceKeyInfo } from '../../src/mdoc/models/device-key-info'
import { IdentifierListInfo } from '../../src/mdoc/models/identifier-list-info'
import { MobileSecurityObject } from '../../src/mdoc/models/mobile-security-object'
import { Status } from '../../src/mdoc/models/status'
import { StatusListInfo } from '../../src/mdoc/models/status-list-info'
import { ValidityInfo } from '../../src/mdoc/models/validity-info'
import { ValueDigests } from '../../src/mdoc/models/value-digests'
import { hex } from '../../src/utils'

const cbor =
  'a66776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496e666fa1696465766963654b6579a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6767646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a30325a'

describe('mobile security object', () => {
  test('parse', () => {
    const mobileSecurityObject = MobileSecurityObject.decode(hex.decode(cbor))

    expect(mobileSecurityObject.version).toStrictEqual('1.0')
    expect(mobileSecurityObject.digestAlgorithm).toStrictEqual('SHA-256')
    expect(mobileSecurityObject.docType).toStrictEqual('org.iso.18013.5.1.mDL')

    expect(mobileSecurityObject.validityInfo).toBeInstanceOf(ValidityInfo)
    expect(mobileSecurityObject.valueDigests).toBeInstanceOf(ValueDigests)
    expect(mobileSecurityObject.deviceKeyInfo).toBeInstanceOf(DeviceKeyInfo)
    expect(mobileSecurityObject.status).toBeUndefined()
  })

  test('round-trip with status list', () => {
    const original = MobileSecurityObject.decode(hex.decode(cbor))
    const withStatus = MobileSecurityObject.create({
      digestAlgorithm: original.digestAlgorithm,
      docType: original.docType,
      valueDigests: original.valueDigests,
      deviceKeyInfo: original.deviceKeyInfo,
      validityInfo: original.validityInfo,
      status: Status.create({
        statusList: StatusListInfo.create({
          uri: 'https://issuer.example/status/1',
          idx: 42,
        }),
      }),
    })

    const decoded = MobileSecurityObject.decode(withStatus.encode())
    expect(decoded.status).toBeInstanceOf(Status)
    expect(decoded.status?.statusList?.uri).toBe('https://issuer.example/status/1')
    expect(decoded.status?.statusList?.idx).toBe(42)
    expect(decoded.status?.identifierList).toBeUndefined()
  })

  test('round-trip with identifier list', () => {
    const original = MobileSecurityObject.decode(hex.decode(cbor))
    const id = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const withStatus = MobileSecurityObject.create({
      digestAlgorithm: original.digestAlgorithm,
      docType: original.docType,
      valueDigests: original.valueDigests,
      deviceKeyInfo: original.deviceKeyInfo,
      validityInfo: original.validityInfo,
      status: Status.create({
        identifierList: IdentifierListInfo.create({
          id,
          uri: 'https://issuer.example/identifiers/1',
        }),
      }),
    })

    const decoded = MobileSecurityObject.decode(withStatus.encode())
    expect(decoded.status?.identifierList?.uri).toBe('https://issuer.example/identifiers/1')
    expect(decoded.status?.identifierList?.id).toEqual(id)
    expect(decoded.status?.statusList).toBeUndefined()
  })

  test('round-trip with both status list and identifier list', () => {
    const original = MobileSecurityObject.decode(hex.decode(cbor))
    const withStatus = MobileSecurityObject.create({
      digestAlgorithm: original.digestAlgorithm,
      docType: original.docType,
      valueDigests: original.valueDigests,
      deviceKeyInfo: original.deviceKeyInfo,
      validityInfo: original.validityInfo,
      status: Status.create({
        statusList: StatusListInfo.create({ uri: 'https://issuer.example/status/1', idx: 7 }),
        identifierList: IdentifierListInfo.create({
          id: new Uint8Array([0xab, 0xcd]),
          uri: 'https://issuer.example/identifiers/1',
        }),
      }),
    })

    const decoded = MobileSecurityObject.decode(withStatus.encode())
    expect(decoded.status?.statusList?.idx).toBe(7)
    expect(decoded.status?.identifierList?.id).toEqual(new Uint8Array([0xab, 0xcd]))
  })
})
