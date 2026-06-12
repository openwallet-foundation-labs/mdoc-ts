import {
  CosePayloadMustBeDefinedError,
  cborDecode,
  DataItem,
  MacAlgorithm,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  type Sign1EncodedStructure,
  type Sign1Options,
  SignatureAlgorithm,
  zUint8Array,
} from '@owf/cose'
import { compareBytes } from '@owf/identity-common'
import { fetchStatusList, StatusListCwt } from '@owf/token-status-list'
import z from 'zod'
import type { MdocContext } from '../../context.js'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback.js'
import {
  IdentifierFoundInRevokedListError,
  InvalidAlgorithmError,
  InvalidIdentifierListSignatureError,
  InvalidMessageAuthenticationCode,
  InvalidSignatureError,
  JwtNotSupportForStatusListError,
  NoPublicKeySetOnStatusListError,
  TrustedRevocationCertificatesMustContainAtleastOneCertificateError,
  UnableToExtractX5ChainFromCwtError,
  UnableToExtractX5ChainFromIdentifierListError,
} from '../errors.js'
import { IdentifierListCwt } from './identifier-list-cwt'
import { MobileSecurityObject, type MobileSecurityObjectEncodedStructure } from './mobile-security-object.js'

export type IssuerAuthEncodedStructure = Sign1EncodedStructure
export type IssuerAuthOptions = Omit<Sign1Options, 'payload'> & {
  payload?: Sign1Options['payload'] | MobileSecurityObject
}

export class IssuerAuth extends Sign1 {
  public static create(options: IssuerAuthOptions): IssuerAuth {
    return super.create({
      ...options,
      payload:
        options.payload instanceof MobileSecurityObject
          ? options.payload.encode({ asDataItem: true })
          : (options.payload ?? null),
    }) as IssuerAuth
  }

  // NOTE: currently lazy loaded and validated, but i think that's fine?
  public get mobileSecurityObject(): MobileSecurityObject {
    if (!this.payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const mso = zUint8Array
      .transform((payload) =>
        cborDecode(payload, {
          unwrapTopLevelDataItem: false,
        })
      )
      .pipe(
        z
          .instanceof<typeof DataItem<MobileSecurityObjectEncodedStructure>>(DataItem)
          .transform((di) => MobileSecurityObject.fromEncodedStructure(di.data))
      )
      .parse(this.payload)

    return mso
  }

  public getIssuingCountry(ctx: Pick<MdocContext, 'x509'>) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0]

    return countryName
  }

  public getIssuingStateOrProvince(ctx: Pick<MdocContext, 'x509'>) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0]

    return stateOrProvince
  }

  /**
   * Verifies the MSO's revocation status. Throws on revocation or
   * a CWT-signature failure; succeeds silently otherwise.
   *
   * @todo return the full verified chain for audit / compliance.
   */
  public async verifyStatus(
    {
      now = new Date(),
      checkFreshness,
      trustedStatusCertificates,
    }: {
      now?: Date
      checkFreshness?: boolean
      trustedStatusCertificates?: Uint8Array[]
    },
    ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
  ): Promise<{ statusList?: StatusListCwt; trustedStatusListChain?: Uint8Array[]; identifierList?: IdentifierListCwt; trustedIdentifierListChain?: Uint8Array[] }> {
    const status = this.mobileSecurityObject.status
    if (!status || (!status.statusList && !status.identifierList)) return {}

    if (!trustedStatusCertificates || trustedStatusCertificates.length <= 0) {
      throw new TrustedRevocationCertificatesMustContainAtleastOneCertificateError(
        'Atleast one certificate is required to check the status of the mdoc. Make sure to supply them in the `trustedStatusCertificates` option'
      )
    }

    let statusList: StatusListCwt | undefined
    let trustedStatusListChain: Uint8Array[] | undefined

    if (status.statusList) {
      const { uri, idx } = status.statusList
      const statusListToken = await fetchStatusList({ uri, customFetcher: ctx.fetch, acceptedFormats: ['cwt'] })

      if (typeof statusListToken === 'string') {
        throw new JwtNotSupportForStatusListError(
          'Could not verify status list token. @owf/mdoc currently does not support JWT format for status list, only CWT'
        )
      }

      const cwt = StatusListCwt.fromToken(statusListToken)

      // TODO: we should add this utility section to the cwt/sign1/mac0 class
      // TODO: support multiple ways to set the public key
      const x5c = cwt.protectedHeaders?.headers.get(RegisteredCwtHeaderClaimKey.X5Chain) as
        | Uint8Array
        | Uint8Array[]
        | undefined

      if (!x5c) {
        throw new UnableToExtractX5ChainFromCwtError()
      }

      const algorithm = cwt.protectedHeaders?.headers.get(RegisteredCwtHeaderClaimKey.Algorithm) as SignatureAlgorithm
      const x5chain =
        x5c instanceof Uint8Array
          ? [x5c]
          : Array.isArray(x5c) && x5c.every((e) => e instanceof Uint8Array)
            ? x5c
            : undefined

      if (!x5chain) {
        throw new UnableToExtractX5ChainFromCwtError()
      }

      const [certificate] = x5chain

      const { chain: statusChain } = await ctx.x509.verifyCertificateChain({
        trustedCertificates: trustedStatusCertificates,
        x5chain,
      })

      const publicKey = await ctx.x509.getPublicKey({ certificate, algorithm })
      const alg = algorithm ?? publicKey.algorithm

      if (!publicKey) {
        throw new NoPublicKeySetOnStatusListError()
      }

      if (Object.values(SignatureAlgorithm).includes(alg as SignatureAlgorithm)) {
        if (!(await cwt.verifySignature({ key: publicKey }, ctx.cose.sign1))) {
          throw new InvalidSignatureError('Incorrect signature for CWT statuslist')
        }
      } else if (Object.values(MacAlgorithm).includes(alg as unknown as MacAlgorithm)) {
        if (!(await cwt.verifyAuthenticationCode({ key: publicKey }, ctx.cose.mac0))) {
          throw new InvalidMessageAuthenticationCode('Incorrect message authentication code for CWT status list')
        }
      } else {
        throw new InvalidAlgorithmError(
          `Invalid algorithm (claim ${RegisteredCwtHeaderClaimKey.Algorithm}) set. Value '${alg}', therefore unable to verify the CWT token status list`
        )
      }

      cwt.verifyStatus({ uri, idx, now, checkFreshness })
      statusList = cwt
      trustedStatusListChain = statusChain
    }

    let identifierList: IdentifierListCwt | undefined
    let trustedIdentifierListChain: Uint8Array[] | undefined

    if (status.identifierList) {
      // ISO/IEC 18013-5 second edition § 12.3.6.4 (identifier list).
      // The MSO's `IdentifierListInfo` carries the URI of an
      // `IdentifierListCwt` and the per-MSO `id` (bstr). The list
      // enumerates revoked identifiers; presence == revoked.
      const { uri, id } = status.identifierList
      const cwt = await IdentifierListCwt.fetch(uri, ctx)

      const x5chain = cwt.x5chain
      if (!x5chain || x5chain.length === 0) {
        throw new UnableToExtractX5ChainFromIdentifierListError()
      }

      // Identifier-list CWTs MUST carry an x5chain in the protected
      // header (§ 12.3.6.3); the chain anchors back to a trusted
      // status-cert root so the caller can vet the issuer.
      const { chain: identifierChain } = await ctx.x509.verifyCertificateChain({
        trustedCertificates: trustedStatusCertificates,
        x5chain,
      })

      const [certificate] = x5chain
      const publicKey = await ctx.x509.getPublicKey({ certificate, algorithm: cwt.algorithm })

      if (!(await cwt.verifySignature({ key: publicKey }, ctx.cose.sign1))) {
        throw new InvalidIdentifierListSignatureError('Incorrect signature for CWT identifier list')
      }

      // Spec: revoked iff the MSO's identifier is present in the list.
      if (cwt.includes(id)) {
        const hex = Array.from(id, (b) => b.toString(16).padStart(2, '0')).join('')
        throw new IdentifierFoundInRevokedListError(`Identifier ${hex} found in revoked list at ${uri}`)
      }

      identifierList = cwt
      trustedIdentifierListChain = identifierChain
    }

    return { statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain }
  }

  public async verify(
    options: {
      verificationCallback?: VerificationCallback
      now?: Date
      trustedCertificates?: Array<{ issuance: Uint8Array[]; status?: Uint8Array[] }>
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'x509' | 'cose' | 'fetch'>
  ): Promise<{ trustedIssuanceChain: Uint8Array[]; statusList?: StatusListCwt; trustedStatusListChain?: Uint8Array[]; identifierList?: IdentifierListCwt; trustedIdentifierListChain?: Uint8Array[] }> {
    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback
    const now = options.now ?? new Date()
    const disableCertificateChainValidation = options.disableCertificateChainValidation ?? false
    const disableStatusValidation = options.disableStatusValidation ?? false
    const trustedCertificates = options.trustedCertificates ?? []
    const skewSeconds = options.skewSeconds ?? 30

    const onCheck = onCategoryCheck(verificationCallback, 'ISSUER_AUTH')

    onCheck({
      status: this.getIssuingCountry(ctx) ? 'PASSED' : 'FAILED',
      check: "Country name (C) must be present in the issuer certificate's subject distinguished name",
    })

    let trustedStatusCertificates: Uint8Array[] | undefined
    let trustedIssuanceChain: Uint8Array[] | undefined
    if (!disableCertificateChainValidation) {
      try {
        if (!trustedCertificates || trustedCertificates?.length <= 0) {
          throw new Error('No trusted certificates found. Cannot verify issuer signature.')
        }

        const { chain } = await ctx.x509.verifyCertificateChain({
          trustedCertificates: trustedCertificates.flatMap(({ issuance }) => issuance),
          x5chain: this.certificateChain,
          now,
        })

        trustedIssuanceChain = chain
        trustedStatusCertificates = chain[chain.length - 1]
          ? trustedCertificates.find((tc) => tc.issuance.some((cert) => compareBytes(cert, chain[chain.length - 1])))
              ?.status
          : undefined

        onCheck({
          status: 'PASSED',
          check: 'Issuer certificate must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Issuer certificate must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    let statusList: StatusListCwt | undefined
    let trustedStatusListChain: Uint8Array[] | undefined
    let identifierList: IdentifierListCwt | undefined
    let trustedIdentifierListChain: Uint8Array[] | undefined
    if (!disableStatusValidation) {
      try {
        ;({ statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain } = await this.verifyStatus(
          {
            now,
            checkFreshness: true,
            trustedStatusCertificates,
          },
          ctx
        ))
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Status information must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const publicKey = await ctx.x509.getPublicKey({ certificate: this.certificate, algorithm: this.algorithm })
    const isSignatureValid = await this.verifySignature({ key: publicKey }, ctx.cose.sign1)

    onCheck({
      status: isSignatureValid ? 'PASSED' : 'FAILED',
      check: 'Issuer auth signature is invalid',
    })

    const { validityInfo } = this.mobileSecurityObject

    const { notAfter, notBefore } = await ctx.x509.getCertificateData({
      certificate: this.certificate,
    })

    onCheck({
      status: validityInfo.isSignedBetweenDates(notBefore, notAfter, skewSeconds) ? 'PASSED' : 'FAILED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${notBefore.toUTCString()} to ${notAfter.toUTCString()})`,
    })

    onCheck({
      status:
        validityInfo.isValidFromBeforeNow(now, skewSeconds) && validityInfo.isValidUntilAfterNow(now, skewSeconds)
          ? 'PASSED'
          : 'FAILED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    })

    onCheck({
      status: trustedIssuanceChain ? 'PASSED' : 'FAILED',
      check: 'Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth',
      reason: `Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth`,
    })

    return { trustedIssuanceChain: trustedIssuanceChain as Uint8Array[], statusList, trustedStatusListChain, identifierList, trustedIdentifierListChain }
  }
}
