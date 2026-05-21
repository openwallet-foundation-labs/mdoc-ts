import { hex } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import z from 'zod'
import { DeviceRequest, Holder, SessionTranscript } from '../../src'
import type { VerificationAssessment } from '../../src/mdoc/check-callback'
import { Handover } from '../../src/mdoc/models/handover'
import { mdocContext } from '../context'

// Static fixture from tests/models/device-request.test.ts — a DeviceRequest with
// a single DocRequest whose readerAuth is signed by a self-signed cert chain
// (subject="reader", issuer="reader root", embedded in the COSE_Sign1 x5chain).
const DEVICE_REQUEST_CBOR =
  'a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d626572f57264726976696e675f70726976696c65676573f56a69737375655f64617465f56b6578706972795f64617465f568706f727472616974f46a726561646572417574688443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c067265616465723059301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628dff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f30b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d739dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c589424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf'

class NullHandover extends Handover<null> {
  static get encodingSchema() {
    return z.null()
  }
}

/**
 * Collect every check emitted by Holder.verifyDeviceRequest without throwing
 * on FAILED. Used to assert which checks ran and their statuses.
 */
function collectChecks(): {
  callback: (a: VerificationAssessment) => void
  checks: VerificationAssessment[]
} {
  const checks: VerificationAssessment[] = []
  return {
    checks,
    callback: (a) => {
      checks.push(a)
    },
  }
}

describe('Holder.verifyDeviceRequest with trustedCertificates', () => {
  const sessionTranscript = SessionTranscript.create({
    handover: NullHandover.fromEncodedStructure(null),
  })

  test('without trustedCertificates: no chain-trust check is emitted', async () => {
    const { callback, checks } = collectChecks()

    await Holder.verifyDeviceRequest(
      {
        deviceRequest: DeviceRequest.decode(hex.decode(DEVICE_REQUEST_CBOR)),
        sessionTranscript,
        verificationCallback: callback,
      },
      mdocContext
    )

    const chainChecks = checks.filter((c) => c.check === 'Reader certificate chain must be trusted')
    expect(chainChecks).toHaveLength(0)
  })

  test('with empty trustedCertificates: chain-trust check FAILS', async () => {
    const { callback, checks } = collectChecks()

    await Holder.verifyDeviceRequest(
      {
        deviceRequest: DeviceRequest.decode(hex.decode(DEVICE_REQUEST_CBOR)),
        sessionTranscript,
        verificationCallback: callback,
        trustedCertificates: [],
      },
      mdocContext
    )

    const chainCheck = checks.find((c) => c.check === 'Reader certificate chain must be trusted')
    expect(chainCheck).toBeDefined()
    expect(chainCheck?.status).toBe('FAILED')
    expect(chainCheck?.reason).toContain('No trusted reader certificates')
  })

  test('with an unrelated CA in trustedCertificates: chain-trust check FAILS', async () => {
    const { callback, checks } = collectChecks()

    // 256 bytes of zeros — definitely not a valid X.509 cert, but enough to
    // trigger the chain-validation path and fail the chain build.
    const unrelatedCa = new Uint8Array(256)

    await Holder.verifyDeviceRequest(
      {
        deviceRequest: DeviceRequest.decode(hex.decode(DEVICE_REQUEST_CBOR)),
        sessionTranscript,
        verificationCallback: callback,
        trustedCertificates: [unrelatedCa],
      },
      mdocContext
    )

    const chainCheck = checks.find((c) => c.check === 'Reader certificate chain must be trusted')
    expect(chainCheck).toBeDefined()
    expect(chainCheck?.status).toBe('FAILED')
  })

  test('with the reader leaf cert as a trusted entity: chain-trust check PASSES', async () => {
    // Extract the reader leaf cert from the static fixture's x5chain.
    // The mdocContext implementation accepts a leaf as a trust anchor (see the
    // FIXME comment in context.ts: it's an existing-test allowance, not a
    // recommended production pattern, but it lets us exercise the success path).
    const decoded = DeviceRequest.decode(hex.decode(DEVICE_REQUEST_CBOR))
    const readerAuth = decoded.docRequests[0].readerAuth
    expect(readerAuth).toBeDefined()
    const leafCert = readerAuth?.certificateChain[0]
    expect(leafCert).toBeDefined()

    const { callback, checks } = collectChecks()

    await Holder.verifyDeviceRequest(
      {
        deviceRequest: decoded,
        sessionTranscript,
        verificationCallback: callback,
        trustedCertificates: [leafCert as Uint8Array],
      },
      mdocContext
    )

    const chainCheck = checks.find((c) => c.check === 'Reader certificate chain must be trusted')
    expect(chainCheck).toBeDefined()
    expect(chainCheck?.status).toBe('PASSED')
  })
})
