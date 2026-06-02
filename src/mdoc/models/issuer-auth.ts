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
import { fetchStatusList, StatusListCwt } from '@owf/token-status-list'
import z from 'zod'
import type { MdocContext } from '../../context.js'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback.js'
import {
  InvalidAlgorithmError,
  InvalidMessageAuthenticationCode,
  InvalidSignatureError,
  JwtNotSupportForStatusListError,
  NoPublicKeySetOnStatusListError,
  TrustedRevocationCertificatesMustContainAtleastOneCertificateError,
  UnableToExtractX5ChainFromCwtError,
} from '../errors.js'
import { MobileSecurityObject, type MobileSecurityObjectEncodedStructure } from './mobile-security-object.js'

export type IssuerAuthEncodedStructure = Sign1EncodedStructure
export type IssuerAuthOptions = Omit<Sign1Options, 'payload'> & {
  payload?: Sign1Options['payload'] | MobileSecurityObject
}

export type GetTrustedStatusCertificates = (options: {
  statusListCertificateChain?: Array<Uint8Array>
}) => Promise<{ trustedStatusListCertificateChain?: Array<Uint8Array> }>

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
   * @todo use the certificate provided in the status
   * @todo handle the identifierList
   */
  public async verifyStatus(
    {
      now = new Date(),
      checkFreshness,
      getTrustedStatusCertificates,
    }: {
      now?: Date
      checkFreshness?: boolean
      getTrustedStatusCertificates?: GetTrustedStatusCertificates
    },
    ctx: Pick<MdocContext, 'fetch' | 'x509' | 'cose'>
  ) {
    if (!this.mobileSecurityObject.status) return undefined
    if (!this.mobileSecurityObject.status.statusList) return undefined
    if (this.mobileSecurityObject.status.identifierList) {
      throw new Error('Unable to verify status. Identifier List is not yet implemented')
    }

    const { uri, idx } = this.mobileSecurityObject.status.statusList
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

    const trustedStatusCertificates = await getTrustedStatusCertificates?.({ statusListCertificateChain: x5chain })

    if (!trustedStatusCertificates || trustedStatusCertificates.trustedStatusListCertificateChain?.length === 0) {
      throw new TrustedRevocationCertificatesMustContainAtleastOneCertificateError(
        'Atleast one certificate is required to check the status of the mdoc. Make sure the `getTrustedStatusCertificates` callback is correctly imlpemented.'
      )
    }

    await ctx.x509.verifyCertificateChain({
      trustedCertificates: trustedStatusCertificates.trustedStatusListCertificateChain as Array<Uint8Array>,
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
      // TODO: `publicKey.algorithm` should also be `MacAlgorithm`
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
    return true
  }

  public async verify(
    options: {
      verificationCallback?: VerificationCallback
      now?: Date
      trustedCertificates?: Array<Uint8Array>
      getTrustedStatusCertificates?: GetTrustedStatusCertificates
      disableCertificateChainValidation?: boolean
      disableStatusValidation?: boolean
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'x509' | 'cose' | 'fetch'>
  ) {
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

    if (!disableStatusValidation) {
      try {
        await this.verifyStatus(
          {
            now,
            checkFreshness: true,
            getTrustedStatusCertificates: options.getTrustedStatusCertificates,
          },
          ctx
        )
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Revocation information must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const publicKey = await ctx.x509.getPublicKey({ certificate: this.certificate, algorithm: this.algorithm })
    const isSignatureValid = await this.verifySignature({ key: publicKey }, { verify: ctx.cose.sign1.verify })

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
