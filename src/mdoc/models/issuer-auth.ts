import {
  CosePayloadMustBeDefinedError,
  cborDecode,
  DataItem,
  Sign1,
  type Sign1EncodedStructure,
  type Sign1Options,
  zUint8Array,
} from '@owf/cose'
import { compareBytes } from '@owf/identity-common'
import type { StatusListCwt } from '@owf/token-status-list'
import z from 'zod'
import type { MdocContext } from '../../context.js'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback.js'
import { TrustedRevocationCertificatesMustContainAtleastOneCertificateError } from '../errors.js'
import type { IdentifierListCwt } from './identifier-list-cwt'
import { MobileSecurityObject, type MobileSecurityObjectEncodedStructure } from './mobile-security-object.js'
import { verifyIdentifierListToken, verifyStatusListToken } from './mso-revocation-list'

export type IssuerAuthEncodedStructure = Sign1EncodedStructure
export type IssuerAuthOptions = Omit<Sign1Options, 'payload'> & {
  payload?: Sign1Options['payload'] | MobileSecurityObject
}

export type IssuerAuthVerificationResult = {
  trustedIssuanceChain: Uint8Array[]
  statusList?: StatusListCwt
  trustedStatusListChain?: Uint8Array[]
  identifierList?: IdentifierListCwt
  trustedIdentifierListChain?: Uint8Array[]
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
      skewSeconds,
      checkFreshness,
      trustedStatusCertificates,
    }: {
      now?: Date
      /** Tolerance applied to the `exp` and `iat` of a revocation list. Defaults to 30 seconds. */
      skewSeconds?: number
      checkFreshness?: boolean
      trustedStatusCertificates?: Uint8Array[]
    },
    ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
  ): Promise<{
    statusList?: StatusListCwt
    trustedStatusListChain?: Uint8Array[]
    identifierList?: IdentifierListCwt
    trustedIdentifierListChain?: Uint8Array[]
  }> {
    const status = this.mobileSecurityObject.status
    if (!status || (!status.statusList && !status.identifierList)) return {}

    if (!trustedStatusCertificates || trustedStatusCertificates.length <= 0) {
      throw new TrustedRevocationCertificatesMustContainAtleastOneCertificateError(
        'Atleast one certificate is required to check the status of the mdoc. Make sure to supply them in the `trustedStatusCertificates` option'
      )
    }

    const statusListResult = status.statusList
      ? await verifyStatusListToken(
          {
            statusListInfo: status.statusList,
            trustedCertificates: trustedStatusCertificates,
            now,
            skewSeconds,
            checkFreshness,
          },
          ctx
        )
      : undefined

    const identifierListResult = status.identifierList
      ? await verifyIdentifierListToken(
          {
            identifierListInfo: status.identifierList,
            trustedCertificates: trustedStatusCertificates,
            now,
            skewSeconds,
            checkFreshness,
          },
          ctx
        )
      : undefined

    return {
      statusList: statusListResult?.statusListCwt,
      trustedStatusListChain: statusListResult?.chain,
      identifierList: identifierListResult?.identifierListCwt,
      trustedIdentifierListChain: identifierListResult?.chain,
    }
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
  ): Promise<IssuerAuthVerificationResult> {
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
            skewSeconds,
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
      check:
        'Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth',
      reason:
        'Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth',
    })

    return {
      trustedIssuanceChain: trustedIssuanceChain as Uint8Array[],
      statusList,
      trustedStatusListChain,
      identifierList,
      trustedIdentifierListChain,
    }
  }
}
