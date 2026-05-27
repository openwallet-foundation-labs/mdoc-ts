import { CborStructure, type CoseKey, MacAlgorithm, TypedMap, typedMap } from '@owf/cose'
import { z } from 'zod'
import type { MdocContext } from '../../context'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac, type DeviceMacEncodedStructure } from './device-mac'
import { DeviceSignature, type DeviceSignatureEncodedStructure } from './device-signature'
import type { Document } from './document'
import type { SessionTranscript } from './session-transcript'

const deviceAuthSchema = typedMap([
  ['deviceSignature', z.instanceof(DeviceSignature).exactOptional()],
  ['deviceMac', z.instanceof(DeviceMac).exactOptional()],
] as const).refine(
  (map) => [map.get('deviceMac'), map.get('deviceSignature')].filter((i) => i !== undefined).length === 1,
  { error: () => 'deviceAuth must contain either a deviceMac or deviceSignature, but not both or neither' }
)

export type DeviceAuthDecodedStructure = z.output<typeof deviceAuthSchema>
export type DeviceAuthEncodedStructure = z.input<typeof deviceAuthSchema>

export type DeviceAuthOptions = {
  deviceSignature?: DeviceSignature
  deviceMac?: DeviceMac
}

export class DeviceAuth extends CborStructure<DeviceAuthEncodedStructure, DeviceAuthDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceAuthSchema.in, deviceAuthSchema.out, {
      decode: (input) => {
        const map: DeviceAuthDecodedStructure = TypedMap.fromMap(input)

        if (input.has('deviceSignature')) {
          map.set(
            'deviceSignature',
            DeviceSignature.fromEncodedStructure(input.get('deviceSignature') as DeviceSignatureEncodedStructure)
          )
        }
        if (input.has('deviceMac')) {
          map.set('deviceMac', DeviceMac.fromEncodedStructure(input.get('deviceMac') as DeviceMacEncodedStructure))
        }
        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        const deviceSignature = output.get('deviceSignature')
        if (deviceSignature) {
          map.set('deviceSignature', deviceSignature.encodedStructure)
        }
        const deviceMac = output.get('deviceMac')
        if (deviceMac) {
          map.set('deviceMac', deviceMac.encodedStructure)
        }
        return map
      },
    })
  }

  public get deviceSignature() {
    return this.structure.get('deviceSignature')
  }

  public get deviceMac() {
    return this.structure.get('deviceMac')
  }

  public async verify(
    options: {
      document: Document
      verificationCallback?: VerificationCallback
      ephemeralMacPrivateKey?: CoseKey
      sessionTranscript: SessionTranscript | Uint8Array
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'DEVICE_AUTH')

    const { deviceKey } = options.document.issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo

    const deviceMac = this.structure.get('deviceMac')
    const deviceSignature = this.structure.get('deviceSignature')

    if (!deviceMac && !deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      })
      return
    }

    const deviceAuthenticationBytes = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      docType: options.document.docType,
      deviceNamespaces: options.document.deviceSigned.deviceNamespaces,
    }).encode({ asDataItem: true })

    if (deviceSignature) {
      try {
        const verificationResult = await ctx.cose.sign1.verify({
          toBeVerified: deviceSignature.toBeSigned({ detachedPayload: deviceAuthenticationBytes }),
          key: deviceKey,
          signature: deviceSignature.signature,
        })

        onCheck({
          status: verificationResult ? 'PASSED' : 'FAILED',
          check: 'Device signature must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device signature must be valid',
          reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err instanceof Error ? err.message : 'Unknown error'}`,
        })
      }
      return
    }

    if (deviceMac) {
      if (deviceMac.signatureAlgorithmName !== MacAlgorithm.HS256) {
        onCheck({
          status: 'FAILED',
          check: 'Device MAC must use alg 5 (HMAC 256/256)',
        })
        return
      }

      onCheck({
        status: options.ephemeralMacPrivateKey ? 'PASSED' : 'FAILED',
        check: 'Ephemeral private key must be present when using MAC authentication',
      })

      if (!options.ephemeralMacPrivateKey) {
        return
      }

      try {
        const isValid = await deviceMac.verify(
          {
            publicKey: deviceKey,
            privateKey: options.ephemeralMacPrivateKey,
            sessionTranscript: options.sessionTranscript,
            info: 'EMacKey',
            detachedPayload: deviceAuthenticationBytes,
          },
          ctx
        )

        onCheck({
          status: isValid ? 'PASSED' : 'FAILED',
          check: 'Device MAC must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device MAC must be valid',
          reason: `Unable to verify deviceAuth MAC: ${err instanceof Error ? err.message : 'Unknown error'}`,
        })
      }
    }

    onCheck({
      status: 'FAILED',
      check: 'No Device Signature or Device Mac found on Device Auth',
      reason: 'No Device Signature or Device Mac found on Device Auth',
    })
  }

  public static create(options: DeviceAuthOptions): DeviceAuth {
    const map: DeviceAuthDecodedStructure = new TypedMap([])
    if (options.deviceSignature) {
      map.set('deviceSignature', options.deviceSignature)
    }
    if (options.deviceMac) {
      map.set('deviceMac', options.deviceMac)
    }

    return this.fromDecodedStructure(map)
  }
}
