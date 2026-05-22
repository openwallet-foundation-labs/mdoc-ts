import {
  CosePayloadMustBeDefinedError,
  cborDecode,
  DataItem,
  Sign1,
  type Sign1EncodedStructure,
  type Sign1Options,
  zUint8Array,
} from '@owf/cose'
import { fetchStatusList, StatusListCwt, verifyStatus } from '@owf/token-status-list'
import z from 'zod'
import type { MdocContext } from '../../context.js'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback.js'
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
          : options.payload,
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

  /**
   * @todo use the certificate provided in the status
   * @todo handle the identifierList
   */
  public async verifyStatus(
    { now = new Date(), checkFreshness }: { now?: Date; checkFreshness?: boolean },
    ctx: Pick<MdocContext, 'fetch'>
  ) {
    if (!this.mobileSecurityObject.status) return undefined
    if (!this.mobileSecurityObject.status.statusList) return undefined
    if (this.mobileSecurityObject.status.identifierList) {
      throw new Error('Unable to verify status. Identifier List is not yet implemented')
    }

    const { uri, idx } = this.mobileSecurityObject.status.statusList
    const statusListToken = await fetchStatusList({ uri, customFetcher: ctx.fetch })
    if (typeof statusListToken === 'string') {
      verifyStatus({ uri, idx, now, token: statusListToken, checkFreshness })
      return true
    }
    const cwt = StatusListCwt.fromToken(statusListToken)
    cwt.verifyStatus({ uri, idx, now, checkFreshness })
    return true
  }

  public async verify(
    options: {
      verificationCallback?: VerificationCallback
      now?: Date
      trustedCertificates?: Array<Uint8Array>
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'x509' | 'cose' | 'fetch'>
  ) {
    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback
    const now = options.now ?? new Date()
    const disableCertificateChainValidation = options.disableCertificateChainValidation ?? false
    const disableRevocationCheck = options.disableStatusValidation ?? false
    const trustedCertificates = options.trustedCertificates ?? []
    const skewSeconds = options.skewSeconds ?? 30

    const onCheck = onCategoryCheck(verificationCallback, 'ISSUER_AUTH')

    onCheck({
      status: this.getIssuingCountry(ctx) ? 'PASSED' : 'FAILED',
      check: "Country name (C) must be present in the issuer certificate's subject distinguished name",
    })

    if (!disableCertificateChainValidation) {
      try {
        if (!trustedCertificates[0]) {
          throw new Error('No trusted certificates found. Cannot verify issuer signature.')
        }

        await ctx.x509.verifyCertificateChain({
          trustedCertificates,
          x5chain: this.certificateChain,
          now,
        })

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

    if (!disableRevocationCheck) {
      try {
        await this.verifyStatus({ now, checkFreshness: true }, ctx)
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Revocation information must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const isSignatureValid = await this.verifySignature({}, { x509: ctx.x509, verify: ctx.cose.sign1.verify })

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
  }
}
