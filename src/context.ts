import type { CoseKey, DigestAlgorithm, Mac0, Mac0Context, Sign1Context } from '@owf/cose'

type MaybePromise<T> = Promise<T> | T

export interface MdocContext {
  crypto: {
    random: (length: number) => Uint8Array
    digest: (input: { digestAlgorithm: DigestAlgorithm; bytes: Uint8Array }) => MaybePromise<Uint8Array>
    hdkf: (input: {
      digestAlgorithm?: DigestAlgorithm
      privateKey: Uint8Array
      publicKey: Uint8Array
      salt: Uint8Array
      info: Uint8Array
    }) => MaybePromise<Uint8Array>
  }

  cose: {
    sign1: {
      sign: Sign1Context['sign']
      verify: Sign1Context['verify']
    }

    mac0: {
      sign: Mac0Context['mac']
      verify(input: { mac0: Mac0; key: CoseKey | Uint8Array }): MaybePromise<boolean>
    }
  }

  x509: {
    getIssuerNameField: Sign1Context['x509']['getIssuerNameField']

    getPublicKey: Sign1Context['x509']['getPublicKey']

    verifyCertificateChain: (input: {
      trustedCertificates: Uint8Array[]
      x5chain: Uint8Array[]
      now?: Date
    }) => MaybePromise<void>

    getCertificateData: (input: { certificate: Uint8Array }) => MaybePromise<{
      issuerName: string
      subjectName: string
      serialNumber: string
      thumbprint: string
      notBefore: Date
      notAfter: Date
      pem: string
    }>
  }
}
