import { z } from 'zod'
import { CborStructure } from '../../cbor'
import type { MdocContext } from '../../context'
import { base64url, TypedMap, typedMap } from '../../utils'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { IssuerAuth, type IssuerAuthEncodedStructure } from './issuer-auth'
import { IssuerNamespaces, type IssuerNamespacesEncodedStructure } from './issuer-namespaces'
import type { IssuerSignedItem } from './issuer-signed-item'
import type { Namespace } from './namespace'

const issuerSignedSchema = typedMap([
  ['nameSpaces', z.instanceof(IssuerNamespaces)],
  ['issuerAuth', z.instanceof(IssuerAuth)],
])

export type IssuerSignedDecodedStructure = z.output<typeof issuerSignedSchema>
export type IssuerSignedEncodedStructure = z.input<typeof issuerSignedSchema>

export type IssuerSignedOptions = {
  issuerNamespaces?: IssuerNamespaces
  issuerAuth: IssuerAuth
}

export class IssuerSigned extends CborStructure<IssuerSignedEncodedStructure, IssuerSignedDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(issuerSignedSchema.in, issuerSignedSchema.out, {
      decode: (input) => {
        const map: IssuerSignedDecodedStructure = TypedMap.fromMap(input)

        // Need to transform namespace into class type
        map.set(
          'nameSpaces',
          IssuerNamespaces.fromEncodedStructure(input.get('nameSpaces') as IssuerNamespacesEncodedStructure)
        )

        // Need to transform namespace into class type
        map.set('issuerAuth', IssuerAuth.fromEncodedStructure(input.get('issuerAuth') as IssuerAuthEncodedStructure))

        return map
      },
      encode: (output) => {
        const map = output.toMap() as Map<unknown, unknown>
        map.set('nameSpaces', output.get('nameSpaces').encodedStructure)
        map.set('issuerAuth', output.get('issuerAuth').encodedStructure)

        return map
      },
    })
  }

  public get issuerNamespaces() {
    return this.structure.get('nameSpaces')
  }

  public get issuerAuth() {
    return this.structure.get('issuerAuth')
  }

  public getIssuerNamespace(namespace: Namespace) {
    return this.issuerNamespaces.getIssuerNamespace(namespace)
  }

  public getPrettyClaims(namespace: Namespace) {
    const issuerSignedItems = this.getIssuerNamespace(namespace)
    if (!issuerSignedItems) return undefined

    return issuerSignedItems.reduce((prev, curr) => ({ ...prev, [curr.elementIdentifier]: curr.elementValue }), {})
  }

  public get encodedForOid4Vci() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vci(encoded: string): IssuerSigned {
    return this.decode(base64url.decode(encoded)) as IssuerSigned
  }

  public async verify(
    options: {
      verificationCallback?: VerificationCallback
      now?: Date
      trustedCertificates?: Array<Uint8Array>
      disableCertificateChainValidation?: boolean
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'x509' | 'crypto' | 'cose'>
  ) {
    const { valueDigests, digestAlgorithm } = this.issuerAuth.mobileSecurityObject

    const onCheck = onCategoryCheck(options.verificationCallback ?? defaultVerificationCallback, 'DATA_INTEGRITY')

    onCheck({
      status: digestAlgorithm ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    })

    // Verify the issuer auth
    await this.issuerAuth.verify(options, ctx)

    const namespaces = this.issuerNamespaces?.issuerNamespaces ?? new Map<string, IssuerSignedItem[]>()

    await Promise.all(
      Array.from(namespaces.entries()).map(async ([ns, nsItems]) => {
        onCheck({
          status: valueDigests?.valueDigests.has(ns) ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include digests for namespace: ${ns}`,
        })

        const verifications = await Promise.all(
          nsItems.map(async (ev) => {
            const isValid = await ev.isValid(ns, this.issuerAuth, ctx)
            return { ev, ns, isValid }
          })
        )

        for (const verification of verifications.filter((v) => v.isValid)) {
          onCheck({
            status: 'PASSED',
            check: `The calculated digest for ${ns}/${verification.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
          })
        }

        for (const verification of verifications.filter((v) => !v.isValid)) {
          onCheck({
            status: 'FAILED',
            check: `The calculated digest for ${ns}/${verification.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
          })
        }

        if (ns === 'org.iso.18013.5.1') {
          const certificateData = await ctx.x509.getCertificateData({
            certificate: this.issuerAuth.certificate,
          })
          if (!certificateData.issuerName) {
            onCheck({
              status: 'FAILED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason:
                "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
            })
          } else {
            const invalidCountry = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
              .find((v) => !v.isValid || !v.ev.matchCertificate(this.issuerAuth, ctx))

            onCheck({
              status: invalidCountry ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason: invalidCountry
                ? `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${this.issuerAuth.getIssuingCountry(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })

            const invalidJurisdiction = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
              .find((v) => !v.isValid || !v.ev.matchCertificate(this.issuerAuth, ctx))

            onCheck({
              status: invalidJurisdiction ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
              reason: invalidJurisdiction
                ? `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${this.issuerAuth.getIssuingStateOrProvince(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })
          }
        }
      })
    )
  }

  public static create(options: IssuerSignedOptions): IssuerSigned {
    const map: IssuerSignedDecodedStructure = new TypedMap([])

    if (options.issuerNamespaces) {
      map.set('nameSpaces', options.issuerNamespaces)
    }

    map.set('issuerAuth', options.issuerAuth)

    return this.fromDecodedStructure(map)
  }
}
