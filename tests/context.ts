import crypto, { timingSafeEqual } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { coseKeyToJwkClaim } from '@owf/cose'
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
        const { tag, toBeAuthenticated, key } = input
        return timingSafeEqual(tag, hmac(sha256, key instanceof CoseKey ? key.privateKey : key, toBeAuthenticated))
      },
    },
    sign1: {
      sign: async (input) => {
        const { key, toBeSigned } = input
        return p256.sign(toBeSigned, key.privateKey, { format: 'compact' })
      },
      verify: async (input) => {
        const { signature, key, toBeVerified } = input

        // lowS is needed after upgrade of @noble/curves to keep existing tests passing
        return p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, {
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

      const key = await importX509(certificate.toString(), coseKeyToJwkClaim.algorithm(input.algorithm), {
        extractable: true,
      })

      return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>)
    },

    verifyCertificateChain: async (input) => {
      const { trustedCertificates, x5chain: certificateChain } = input
      if (certificateChain.length === 0) throw new Error('Certificate chain is empty')

      const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0])
      const certificatesToBuildChain = [...certificateChain, ...(trustedCertificates ?? [])].map(
        (c) => new x509.X509Certificate(c)
      )

      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: certificatesToBuildChain,
      })

      const chain = await certificateChainBuilder.build(parsedLeafCertificate)

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      let parsedChain = chain.reverse()

      // We allow longer parsed chain, in case the root cert was not part of the chain, but in the
      // list of trusted certificates
      if (parsedChain.length < certificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
      }

      let previousCertificate: X509Certificate | undefined

      if (trustedCertificates) {
        const parsedTrustedCertificates = trustedCertificates.map(
          (trustedCertificate) => new X509Certificate(trustedCertificate)
        )

        const trustedCertificateIndex = parsedChain.findIndex((cert) =>
          parsedTrustedCertificates.some((tCert) => cert.equal(tCert))
        )

        if (trustedCertificateIndex === -1) {
          throw new Error('No trusted certificate was found while validating the X.509 chain')
        }

        if (trustedCertificateIndex > 0) {
          // When we trust a certificate other than the first certificate in the provided chain we keep a reference to the
          // previous certificate as we need the key of this certificate to verify the first certificate in the chain as
          // it's not self-sigend.
          previousCertificate = parsedChain[trustedCertificateIndex - 1]

          // Pop everything off before the index of the trusted certificate (those are more root) as it is not relevant for validation
          parsedChain = parsedChain.slice(trustedCertificateIndex)
        }
      }

      // Verify the certificate with the publicKey of the certificate above
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i]
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined

        // The only scenario where this will trigger is if the trusted certificates and the x509 chain both do not contain the
        // intermediate/root certificate needed. E.g. for ISO 18013-5 mDL the root cert MUST NOT be in the chain. If the signer
        // certificate is then trusted, it will fail, as we can't verify the signer certifciate without having access to the signer
        // key of the root certificate.
        // See also https://github.com/openid/OpenID4VCI/issues/62
        //
        // In this case we could skip the signature verification (not other verifications), as we already trust the signer certificate,
        // but i think the purpose of ISO 18013-5 mDL is that you trust the root certificate. If we can't verify the whole chain e.g.
        // when we receive a credential we have the chance it will fail later on.
        const skipSignatureVerification = i === 0 && trustedCertificates && !publicKey
        // NOTE: at some point we might want to change this to throw an error instead of skipping the signature verification of the trusted
        // but it would basically prevent mDOCs from unknown issuers to be verified in the wallet. Verifiers should only trust the root certificate
        // anyway.
        // if (i === 0 && trustedCertificates && cert.issuer !== cert.subject && !publicKey) {
        //   throw new X509Error(
        //     'Unable to verify the certificate chain. A non-self-signed certificate is the first certificate in the chain, and no parent certificate was found in the trusted certificates, meaning the first certificate in the chain cannot be verified. Ensure the certificate is added '
        //   )
        // }

        if (!skipSignatureVerification) {
          await cert.verify({
            publicKey,
          })
        }
        previousCertificate = cert
      }

      return { chain: parsedChain.map((cert) => new Uint8Array(cert.rawData)) }
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
