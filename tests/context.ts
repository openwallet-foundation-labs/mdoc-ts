import crypto, { timingSafeEqual } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '@owf/identity-common'
import { hkdf } from '@panva/hkdf'
import * as x509 from '@peculiar/x509'
import { X509Certificate } from '@peculiar/x509'
import { exportJWK, importX509 } from 'jose'
import { CoseKey, type MdocContext } from '../src'

export const mdocContext: MdocContext = {
  fetch,
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      // Need to cast as Uint8Array<ArrayBuffer> since newer TypeScript versions made Uint8Array generic
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes as Uint8Array<ArrayBuffer>)
      return new Uint8Array(digest)
    },
    random: (length: number) => {
      return crypto.getRandomValues(new Uint8Array(length))
    },
    hdkf: async (input) => {
      const { digestAlgorithm: da, salt, info, publicKey, privateKey } = input
      const ikm = p256.getSharedSecret(privateKey, publicKey, true).slice(1)
      const digestAlgorithm = da === 'SHA-384' ? 'sha384' : da === 'SHA-512' ? 'sha512' : 'sha256'
      return await hkdf(digestAlgorithm, ikm, salt, info, 32)
    },
  },

  cose: {
    mac0: {
      authenticate: async (input) => {
        const { key, toBeAuthenticated } = input
        const keyBytes = key instanceof CoseKey ? key.privateKey : key
        return hmac(sha256, keyBytes, toBeAuthenticated)
      },
      verify: async (input) => {
        const { mac0, key } = input
        return timingSafeEqual(
          mac0.tag,
          hmac(sha256, key instanceof CoseKey ? key.privateKey : key, mac0.toBeAuthenticated)
        )
      },
    },
    sign1: {
      sign: async (input) => {
        const { key, toBeSigned } = input
        return p256.sign(toBeSigned, key.privateKey, { format: 'compact' })
      },
      verify: async (input) => {
        const { sign1, key } = input

        // lowS is needed after upgrade of @noble/curves to keep existing tests passing
        return p256.verify(sign1.signature, sign1.toBeSigned, key instanceof CoseKey ? key.publicKey : key, {
          lowS: false,
        })
      },
    },
  },

  x509: {
    getIssuerNameField: (input) => {
      const certificate = new X509Certificate(input.certificate)
      return certificate.issuerName.getField(input.field)
    },
    getPublicKey: async (input) => {
      const certificate = new X509Certificate(input.certificate)

      const key = await importX509(certificate.toString(), input.alg, {
        extractable: true,
      })

      return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>)
    },

    verifyCertificateChain: async (input: {
      trustedCertificates: Array<Uint8Array>
      x5chain: Array<Uint8Array>
      now?: Date
    }) => {
      const { trustedCertificates, x5chain: mdocCertificateChain } = input
      if (mdocCertificateChain.length === 0) throw new Error('Certificate chain is empty')

      const parsedLeafCertificate = new x509.X509Certificate(mdocCertificateChain[0])
      const parsedMdocCertificates = mdocCertificateChain.map((c) => new x509.X509Certificate(c))
      const parsedTrustedCertificates = trustedCertificates.map((c) => new x509.X509Certificate(c))

      // Use both trusted and mdoc certificate to build chain
      const certificatesToBuildChain = [...parsedMdocCertificates, ...parsedTrustedCertificates]
      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: certificatesToBuildChain,
      })

      const chain = await certificateChainBuilder.build(parsedLeafCertificate)

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      let parsedChain = chain.map((c) => new x509.X509Certificate(c.rawData)).reverse()

      // We allow longer parsed chain, in case the root cert was not part of the chain, but in the
      // list of trusted certificates
      if (parsedChain.length < mdocCertificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
      }

      const trustedCertificateIndex = parsedChain.findIndex((cert) =>
        parsedTrustedCertificates.some((tCert) => cert.equal(tCert))
      )

      if (trustedCertificateIndex === -1) {
        throw new Error('No trusted certificate was found while validating the X.509 chain')
      }

      // FIXME: we should remove this, and update all tests to use root cert for verification
      // as the 'correct' way to verify is only using the root
      // Currently if you provide a leaf certificate as trusted entities it will not verify any
      // certificate, as we don't have the root, and can't verify the leaf without the authority key
      // so basically it just does an equals match on whether the certificate is equal with a trusted
      // certificate. But that also means you skip verification of the validity time of the cert
      parsedChain = parsedChain.slice(0, trustedCertificateIndex)

      // Verify the certificate with the publicKey of the certificate above
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i]
        const previousCertificate = parsedChain[i - 1]
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined
        await cert?.verify({ publicKey, date: input.now ?? new Date() })
      }
    },
    getCertificateData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate)
      const thumbprint = await certificate.getThumbprint(crypto)
      const thumbprintHex = hex.encode(new Uint8Array(thumbprint))
      return {
        issuerName: certificate.issuerName.toString(),
        subjectName: certificate.subjectName.toString(),
        pem: certificate.toString(),
        serialNumber: certificate.serialNumber,
        thumbprint: thumbprintHex,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      }
    },
  },
}

export const deterministicMdocContext = {
  ...mdocContext,
  crypto: {
    ...mdocContext.crypto,
    random: (len: number) =>
      hex.decode('9bdb72498967865710108af43959f90c1b6aac9687bedd1fa53dd0d2103fa5d0').slice(0, len),
  },
}
