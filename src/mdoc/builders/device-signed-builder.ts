import {
  type CoseKey,
  type MacAlgorithm,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  type SignatureAlgorithm,
  UnprotectedHeaders,
} from '@owf/cose'
import { base64, stringToBytes } from '@owf/identity-common'
import type { MdocContext } from '../../context'
import {
  DeviceAuth,
  DeviceMac,
  DeviceNamespaces,
  DeviceSignature,
  DeviceSigned,
  DeviceSignedItems,
  type DocType,
  type Namespace,
  type SessionTranscript,
} from '../models'
import { DeviceAuthentication } from '../models/device-authentication'

export class DeviceSignedBuilder {
  private docType: DocType
  private namespaces: DeviceNamespaces
  private ctx: Pick<MdocContext, 'cose' | 'crypto'>

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.docType = docType
    this.namespaces = DeviceNamespaces.create({ deviceNamespaces: new Map() })
    this.ctx = ctx
  }

  public addDeviceNamespace(namespace: Namespace, value: Record<string, unknown>) {
    const deviceSignedItems =
      this.namespaces.deviceNamespaces.get(namespace) ?? DeviceSignedItems.create({ deviceSignedItems: new Map() })

    for (const [k, v] of Object.entries(value)) {
      deviceSignedItems.deviceSignedItems.set(k, v)
    }

    this.namespaces.deviceNamespaces.set(namespace, deviceSignedItems)

    return this
  }

  public async sign(options: {
    signingKey: CoseKey
    algorithm: SignatureAlgorithm
    sessionTranscript: SessionTranscript
    derCertificate: string
  }): Promise<DeviceSigned> {
    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({
      unprotectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.signingKey.keyId) {
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, options.signingKey.keyId)
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceSignature = DeviceSignature.create({
      unprotectedHeaders,
      protectedHeaders,
      payload: null,
    })

    await deviceSignature.sign(
      {
        signingKey: options.signingKey,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
      },
      { sign: this.ctx.cose.sign1.sign }
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
        deviceSignature,
      }),
    })
  }

  public async tag(options: {
    publicKey: CoseKey
    privateKey: CoseKey
    sessionTranscript: SessionTranscript
    algorithm: MacAlgorithm
    derCertificate: string
  }): Promise<DeviceSigned> {
    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({
      unprotectedHeaders: new Map([[RegisteredCwtHeaderClaimKey.X5Chain, base64.decode(options.derCertificate)]]),
    })

    if (options.privateKey.keyId) {
      unprotectedHeaders.headers?.set(RegisteredCwtHeaderClaimKey.KeyId, options.privateKey.keyId)
    }

    const deviceAuthentication = DeviceAuthentication.create({
      sessionTranscript: options.sessionTranscript,
      deviceNamespaces: this.namespaces,
      docType: this.docType,
    })

    const deviceMac = DeviceMac.create({
      unprotectedHeaders,
      protectedHeaders,
      payload: null,
    })

    const salt = await this.ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: options.sessionTranscript.encode() })

    const derivedKey = await this.ctx.crypto.hdkf({
      privateKey: options.privateKey.privateKey,
      publicKey: options.publicKey.publicKey,
      info: stringToBytes('EMacKey'),
      salt,
    })

    const deviceMacWithTag = await deviceMac.authenticate(
      {
        key: derivedKey,
        detachedPayload: deviceAuthentication.encode({ asDataItem: true }),
      },
      this.ctx.cose.mac0
    )

    return DeviceSigned.create({
      deviceNamespaces: this.namespaces,
      deviceAuth: DeviceAuth.create({
        deviceMac: deviceMacWithTag,
      }),
    })
  }
}
