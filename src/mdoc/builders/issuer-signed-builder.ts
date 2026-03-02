import type { MdocContext } from '../../context'
import {
  type CoseKey,
  type DigestAlgorithm,
  Header,
  ProtectedHeaders,
  type SignatureAlgorithm,
  UnprotectedHeaders,
} from '../../cose'
import { randomUnsignedInteger } from '../../utils/randomUnsignedInteger'
import {
  DeviceKeyInfo,
  type DeviceKeyInfoOptions,
  type Digest,
  type DigestId,
  type DocType,
  IssuerAuth,
  IssuerNamespaces,
  IssuerSigned,
  IssuerSignedItem,
  MobileSecurityObject,
  type Namespace,
  ValidityInfo,
  type ValidityInfoOptions,
  ValueDigests,
  type ValueDigestsStructure,
} from '../models'

export class IssuerSignedBuilder {
  private docType: DocType
  private namespaces: IssuerNamespaces
  private ctx: Pick<MdocContext, 'cose' | 'crypto'>

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.docType = docType
    this.ctx = ctx
    this.namespaces = IssuerNamespaces.create({ issuerNamespaces: new Map() })
  }

  public addIssuerNamespace(namespace: Namespace, values: Record<string, unknown> | Map<string, unknown>) {
    const issuerNamespace = this.namespaces.getIssuerNamespace(namespace) ?? []

    const entries = values instanceof Map ? Array.from(values.entries()) : Object.entries(values)

    const issuerSignedItems = entries.map(([key, value]) =>
      IssuerSignedItem.fromOptions({
        digestId: randomUnsignedInteger(this.ctx),
        random: this.ctx.crypto.random(32),
        elementIdentifier: key,
        elementValue: value,
      })
    )
    issuerNamespace.push(...issuerSignedItems)

    this.namespaces.setIssuerNamespace(namespace, issuerNamespace)

    return this
  }

  private async convertIssuerNamespacesIntoValueDigests(digestAlgorithm: DigestAlgorithm): Promise<ValueDigests> {
    const valueDigests: ValueDigestsStructure = new Map()

    for (const [namespace, issuerSignedItems] of this.namespaces.issuerNamespaces) {
      const digests = new Map<DigestId, Digest>()
      for (const issuerSignedItem of issuerSignedItems) {
        const digest = await this.ctx.crypto.digest({
          digestAlgorithm,
          bytes: issuerSignedItem.encode({ asDataItem: true }),
        })

        digests.set(issuerSignedItem.digestId, digest)
      }
      valueDigests.set(namespace, digests)
    }

    return ValueDigests.create({ digests: valueDigests })
  }

  public async sign(options: {
    signingKey: CoseKey
    algorithm: SignatureAlgorithm
    digestAlgorithm: DigestAlgorithm
    validityInfo: ValidityInfo | ValidityInfoOptions
    deviceKeyInfo: DeviceKeyInfo | DeviceKeyInfoOptions
    certificates: [Uint8Array, ...Uint8Array[]]
  }): Promise<IssuerSigned> {
    const validityInfo =
      options.validityInfo instanceof ValidityInfo ? options.validityInfo : ValidityInfo.create(options.validityInfo)

    const deviceKeyInfo =
      options.deviceKeyInfo instanceof DeviceKeyInfo
        ? options.deviceKeyInfo
        : DeviceKeyInfo.create(options.deviceKeyInfo)

    const mso = MobileSecurityObject.create({
      docType: this.docType,
      validityInfo,
      digestAlgorithm: options.digestAlgorithm,
      deviceKeyInfo,
      valueDigests: await this.convertIssuerNamespacesIntoValueDigests(options.digestAlgorithm),
    })

    const protectedHeaders = ProtectedHeaders.create({
      protectedHeaders: new Map([[Header.Algorithm, options.algorithm]]),
    })

    const unprotectedHeaders = UnprotectedHeaders.create({
      unprotectedHeaders: new Map([
        [Header.X5Chain, options.certificates.length === 1 ? options.certificates[0] : options.certificates],
      ]),
    })

    if (options.signingKey.keyId) {
      unprotectedHeaders.headers?.set(Header.KeyId, options.signingKey.keyId)
    }

    const issuerAuth = await IssuerAuth.create(
      {
        payload: mso,
        unprotectedHeaders,
        protectedHeaders,
        signingKey: options.signingKey,
      },
      this.ctx
    )

    return IssuerSigned.create({
      issuerNamespaces: this.namespaces,
      issuerAuth,
    })
  }
}
