import { z } from 'zod'
import { CborStructure, DataItem } from '../../cbor'
import type { MdocContext } from '../../context'
import { DeviceEngagement, type DeviceEngagementEncodedStructure } from './device-engagement'
import { EReaderKey, type EReaderKeyEncodedStructure } from './e-reader-key'
import { Handover } from './handover'
import { NfcHandover } from './nfc-handover'
import {
  Oid4vpDcApiDraft24HandoverInfo,
  type Oid4vpDcApiDraft24HandoverInfoOptions,
} from './oid4vp-dc-api-draft24-handover-info'
import { Oid4vpDcApiHandover } from './oid4vp-dc-api-handover'
import { Oid4vpDcApiHandoverInfo, type Oid4vpDcApiHandoverInfoOptions } from './oid4vp-dc-api-handover-info'
import { Oid4vpDraft18Handover } from './oid4vp-draft18-handover'
import { Oid4vpHandover } from './oid4vp-handover'
import { Oid4vpHandoverInfo, type Oid4vpHandoverInfoOptions } from './oid4vp-handover-info'
import { Oid4vpIaeHandover } from './oid4vp-iae-handover'
import { Oid4vpIaeHandoverInfo, type Oid4vpIaeHandoverInfoOptions } from './oid4vp-iae-handover-info'
import { QrHandover } from './qr-handover'

const supportedHandoverStructures = [
  Oid4vpHandover,
  Oid4vpDcApiHandover,
  Oid4vpIaeHandover,
  NfcHandover,
  QrHandover,
  Oid4vpDraft18Handover,
] as const

export const sessionTranscriptEncodedSchema = z.tuple([
  z.instanceof<typeof DataItem<DeviceEngagementEncodedStructure>>(DataItem).nullable(),
  z.instanceof<typeof DataItem<EReaderKeyEncodedStructure>>(DataItem).nullable(),
  z.unknown(),
])

const sessionTranscriptDecodedSchema = z.object({
  deviceEngagement: z.instanceof(DeviceEngagement).nullable(),
  eReaderKey: z.instanceof(EReaderKey).nullable(),
  handover: z.instanceof(Handover),
})

export type SessionTranscriptDecodedStructure = z.infer<typeof sessionTranscriptDecodedSchema>
export type SessionTranscriptEncodedStructure = z.infer<typeof sessionTranscriptEncodedSchema>

export type SessionTranscriptOptions = {
  deviceEngagement?: DeviceEngagement
  eReaderKey?: EReaderKey
  handover: Handover
}

export class SessionTranscript extends CborStructure<
  SessionTranscriptEncodedStructure,
  SessionTranscriptDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(sessionTranscriptEncodedSchema, sessionTranscriptDecodedSchema, {
      decode: ([deviceEngagementDataItem, eReaderKeyDataItem, handoverData]): SessionTranscriptDecodedStructure => {
        // TODO: this checks if it can be decoded, a smarter check could see that the handover
        // is e.g. OpenId4VP handover but a value in that handover is incorrect
        let handover: SessionTranscriptDecodedStructure['handover'] | null = null
        for (const HandoverStructure of supportedHandoverStructures) {
          handover = (HandoverStructure as typeof NfcHandover).tryDecodeHandover(handoverData)
          if (handover) break
        }

        if (!handover) {
          throw new Error('Could not establish handover structure for session transcript')
        }

        const deviceEngagement = deviceEngagementDataItem
          ? DeviceEngagement.fromEncodedStructure(deviceEngagementDataItem.data)
          : null
        const eReaderKey = eReaderKeyDataItem ? EReaderKey.fromEncodedStructure(eReaderKeyDataItem.data) : null

        return {
          deviceEngagement,
          eReaderKey,
          handover,
        }
      },
      encode: ({ deviceEngagement, eReaderKey, handover }): SessionTranscriptEncodedStructure => {
        if (handover.requiresDeviceEngagement && !deviceEngagement) {
          throw new Error(
            `Session transcript has no deviceEngagement but ${handover.constructor.name} handover requires deviceEngagement`
          )
        }

        if (!handover.requiresDeviceEngagement && deviceEngagement) {
          throw new Error(
            `Session transcript has deviceEngagement but ${handover.constructor.name} handover does not expect deviceEngagement.`
          )
        }

        if (handover.requiresReaderKey && !eReaderKey) {
          throw new Error(
            `Session transcript has no eReaderKey but ${handover.constructor.name} handover requires eReaderKey`
          )
        }

        if (!handover.requiresReaderKey && eReaderKey) {
          throw new Error(
            `Session transcript has eReaderKey but ${handover.constructor.name} handover does not expect eReaderKey.`
          )
        }

        return [
          deviceEngagement ? DataItem.fromData(deviceEngagement.encodedStructure) : null,
          eReaderKey ? DataItem.fromData(eReaderKey.encodedStructure) : null,
          handover.encodedStructure,
        ]
      },
    })
  }

  public get deviceEngagement() {
    return this.structure.deviceEngagement
  }

  public get eReaderKey() {
    return this.structure.eReaderKey
  }

  public get handover() {
    return this.structure.handover
  }

  public static create(options: SessionTranscriptOptions): SessionTranscript {
    return this.fromDecodedStructure({
      deviceEngagement: options.deviceEngagement ?? null,
      eReaderKey: options.eReaderKey ?? null,
      handover: options.handover,
    })
  }

  /**
   * Create a SessionTranscript for QR handover (ISO 18013-5 proximity presentation).
   *
   * For QR handover, exact CBOR bytes matter for session key derivation.
   * Use DeviceEngagement.decode() and EReaderKey.decode() to preserve original bytes -
   * calling encode() on decoded objects will return the identical bytes.
   */
  public static forQrHandover(options: { deviceEngagement: DeviceEngagement; eReaderKey: EReaderKey }) {
    return this.fromDecodedStructure({
      deviceEngagement: options.deviceEngagement,
      eReaderKey: options.eReaderKey,
      handover: QrHandover.create(),
    })
  }

  public static async forOid4VpDcApiDraft24(
    options: Oid4vpDcApiDraft24HandoverInfoOptions,
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const info = Oid4vpDcApiDraft24HandoverInfo.create(options)
    const handover = await Oid4vpDcApiHandover.create({ oid4vpDcApiHandoverInfo: info }, ctx)

    return this.fromDecodedStructure({ deviceEngagement: null, eReaderKey: null, handover })
  }

  public static async forOid4VpDcApi(options: Oid4vpDcApiHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = Oid4vpDcApiHandoverInfo.create(options)
    const handover = await Oid4vpDcApiHandover.create({ oid4vpDcApiHandoverInfo: info }, ctx)

    return this.fromDecodedStructure({ deviceEngagement: null, eReaderKey: null, handover })
  }

  public static async forOid4VpIae(options: Oid4vpIaeHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = Oid4vpIaeHandoverInfo.create(options)
    const handover = await Oid4vpIaeHandover.create({ oid4vpIaeHandoverInfo: info }, ctx)

    return this.fromDecodedStructure({ deviceEngagement: null, eReaderKey: null, handover })
  }

  public static async forOid4Vp(options: Oid4vpHandoverInfoOptions, ctx: Pick<MdocContext, 'crypto'>) {
    const info = Oid4vpHandoverInfo.create(options)
    const handover = await Oid4vpHandover.create({ oid4vpHandoverInfo: info }, ctx)

    return this.fromDecodedStructure({ deviceEngagement: null, eReaderKey: null, handover })
  }

  /**
   * Calculate the session transcript bytes as defined in 18013-7 first edition, based
   * on OpenID4VP draft 18.
   */
  public static async forOid4VpDraft18(
    options: { clientId: string; responseUri: string; verifierGeneratedNonce: string; mdocGeneratedNonce: string },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const handover = await Oid4vpDraft18Handover.create(
      {
        clientId: options.clientId,
        nonce: options.verifierGeneratedNonce,
        mdocGeneratedNonce: options.mdocGeneratedNonce,
        responseUri: options.responseUri,
      },
      ctx
    )

    return this.fromDecodedStructure({ deviceEngagement: null, eReaderKey: null, handover })
  }
}
