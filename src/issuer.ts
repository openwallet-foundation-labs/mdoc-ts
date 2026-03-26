import type { MdocContext } from './context'
import { CoseKey, type DigestAlgorithm, type SignatureAlgorithm } from './cose'
import type {
  DeviceKeyInfo,
  DeviceKeyInfoOptions,
  DocType,
  IssuerSigned,
  Namespace,
  ValidityInfo,
  ValidityInfoOptions,
} from './mdoc'
import { IssuerSignedBuilder } from './mdoc/builders'

export class Issuer {
  private isb: IssuerSignedBuilder

  public constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    this.isb = new IssuerSignedBuilder(docType, ctx)
  }

  public addIssuerNamespace(namespace: Namespace, value: Record<string | number, unknown>) {
    this.isb = this.isb.addIssuerNamespace(namespace, value)
    return this
  }

  public async sign(options: {
    signingKey: CoseKey | Record<string | number, unknown>
    algorithm: SignatureAlgorithm
    digestAlgorithm: DigestAlgorithm
    validityInfo: ValidityInfo | ValidityInfoOptions
    deviceKeyInfo: DeviceKeyInfo | DeviceKeyInfoOptions
    certificates: Uint8Array[]
  }): Promise<IssuerSigned> {
    const signingKey = options.signingKey instanceof CoseKey ? options.signingKey : CoseKey.fromJwk(options.signingKey)
    return await this.isb.sign({ ...options, signingKey })
  }
}
