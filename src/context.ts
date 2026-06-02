import type { CoseKey, DigestAlgorithm, Mac0Context, MacAlgorithm, Sign1Context, SignatureAlgorithm } from '@owf/cose'

type MaybePromise<T> = Promise<T> | T

export interface MdocContext {
  fetch: typeof fetch
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

    mac0: Mac0Context
  }

  x509: {
    getIssuerNameField: (options: { certificate: Uint8Array; field: string }) => string[]
    getPublicKey: (options: {
      certificate: Uint8Array
      algorithm?: SignatureAlgorithm | MacAlgorithm
    }) => Promise<CoseKey>

    /**
     *
     * Verify a X.509 certificate chain
     *
     * Return the parsed chain where index 0 is the leaf certificate and the last entry is the X.509 certificate found in the trusted certificates (root)
     *
     */
    verifyCertificateChain: (input: {
      trustedCertificates: Uint8Array[]
      x5chain: Uint8Array[]
      now?: Date
    }) => MaybePromise<{ chain: Uint8Array[] }>

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
