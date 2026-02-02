import { describe, expect, test } from 'vitest'
import { DeviceEngagement } from '../../src/mdoc/models/device-engagement'
import { EReaderKey } from '../../src/mdoc/models/e-reader-key'
import { NfcHandover } from '../../src/mdoc/models/nfc-handover'
import { SessionTranscript } from '../../src/mdoc/models/session-transcript'
import { hex } from '../../src/utils'
import { mdocContext } from '../context'

const cbor =
  'd81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414'

describe('session transcript', () => {
  test('parse', () => {
    const sessionTranscript = SessionTranscript.decode(hex.decode(cbor))

    expect(sessionTranscript.deviceEngagement).toBeInstanceOf(DeviceEngagement)
    expect(sessionTranscript.eReaderKey).toBeInstanceOf(EReaderKey)
    expect(sessionTranscript.handover).toBeInstanceOf(NfcHandover)

    const nh = sessionTranscript.handover as NfcHandover

    expect(nh.selectMessage).toBeDefined()
    expect(nh.requestMessage).toBeDefined()
  })

  test('calculateSessionTranscriptBytesForOid4VpDcApi against OpenID4VP test vector', async () => {
    const sessionTranscript = await SessionTranscript.forOid4VpDcApi(
      {
        origin: 'https://example.com',
        nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
        jwkThumbprint: Buffer.from('4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047', 'hex'),
      },
      mdocContext
    )

    expect(Buffer.from(sessionTranscript.encode()).toString('hex')).toEqual(
      '83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a'
    )
  })

  test('calculate SessionTranscript forOid4VpIae against OpenID4VP test vector', async () => {
    const sessionTranscript = await SessionTranscript.forOid4VpIae(
      {
        interactiveAuthorizationEndpoint: 'https://example.com/iae',
        nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
        jwkThumbprint: Buffer.from('4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047', 'hex'),
      },
      mdocContext
    )

    expect(Buffer.from(sessionTranscript.encode()).toString('hex')).toEqual(
      '83f6f682754f70656e49443456434949414548616e646f7665725820df679426cc1bf8996e8eb549ee078815a87a97c5e95c1c5a8ec39eedca28a838'
    )
  })

  test('calculateSessionTranscriptBytesForOid4Vp against OpenID4VP test vector', async () => {
    const sessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'x509_san_dns:example.com',
        nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
        jwkThumbprint: Buffer.from('4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047', 'hex'),
        responseUri: 'https://example.com/response',
      },
      mdocContext
    )

    expect(Buffer.from(sessionTranscript.encode()).toString('hex')).toEqual(
      '83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac'
    )
  })
})
