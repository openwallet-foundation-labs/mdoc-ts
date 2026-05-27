import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { ReaderAuth, RegisteredCwtHeaderClaimKey } from '../../src'

const cbor =
  '8443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c067265616465723059301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628dff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f30b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d739dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c589424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf'

describe('reader auth', () => {
  test('parse', () => {
    const readerAuth = ReaderAuth.decode(hex.decode(cbor))

    expect(readerAuth.signature).toBeDefined()
    expect(readerAuth.payload).toBeNull()
    expect(readerAuth.unprotectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.X5Chain)).toBeTruthy()
    expect(readerAuth.protectedHeaders.headers?.has(RegisteredCwtHeaderClaimKey.Algorithm)).toBeTruthy()

    expect(() => readerAuth.toBeSigned()).toThrow()
  })
})
