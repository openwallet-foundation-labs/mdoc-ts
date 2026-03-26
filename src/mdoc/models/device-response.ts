import { z } from 'zod'
import { CborStructure } from '../../cbor'
import type { MdocContext } from '../../context'
import { type CoseKey, Header, ProtectedHeaders, UnprotectedHeaders } from '../../cose'
import { base64url, TypedMap, typedMap } from '../../utils'
import { findIssuerSigned } from '../../utils/findIssuerSigned'
import { limitDisclosureToDeviceRequestNameSpaces } from '../../utils/limitDisclosure'
import { verifyDocRequestsWithIssuerSigned } from '../../utils/verifyDocRequestsWithIssuerSigned'
import { defaultVerificationCallback, type VerificationCallback } from '../check-callback'
import { EitherSignatureOrMacMustBeProvidedError } from '../errors'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import { Document, type DocumentEncodedStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import { IssuerSigned } from './issuer-signed'
import type { SessionTranscript } from './session-transcript'

const deviceResponseEncodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.unknown()).exactOptional()],
  ['documentErrors', z.array(z.unknown()).exactOptional()],
] as const)

const deviceResponseDecodedSchema = typedMap([
  ['version', z.string()],
  ['status', z.number()],
  ['documents', z.array(z.instanceof(Document)).exactOptional()],
  ['documentErrors', z.array(z.instanceof(DocumentError)).exactOptional()],
] as const)

export type DeviceResponseEncodedStructure = z.input<typeof deviceResponseEncodedSchema>
export type DeviceResponseDecodedStructure = z.output<typeof deviceResponseDecodedSchema>

export type DeviceResponseOptions = {
  version?: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status?: number
}

export class DeviceResponse extends CborStructure<DeviceResponseEncodedStructure, DeviceResponseDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(deviceResponseEncodedSchema.in, deviceResponseDecodedSchema.out, {
      decode: (input) => {
        const map = TypedMap.fromMap(input) as DeviceResponseDecodedStructure

        if (input.has('documents')) {
          map.set(
            'documents',
            (input.get('documents') as unknown[]).map((d) =>
              Document.fromEncodedStructure(d as DocumentEncodedStructure)
            )
          )
        }

        if (input.has('documentErrors')) {
          map.set(
            'documentErrors',
            (input.get('documentErrors') as unknown[]).map((d) =>
              DocumentError.fromEncodedStructure(d as DocumentErrorStructure)
            )
          )
        }

        return map
      },
      encode: (output) => {
        const map: Map<unknown, unknown> = output.toMap()

        const documents = output.get('documents')
        if (documents !== undefined) {
          map.set(
            'documents',
            documents.map((d) => d.encodedStructure)
          )
        }

        const documentErrors = output.get('documentErrors')
        if (documentErrors !== undefined) {
          map.set(
            'documentErrors',
            documentErrors.map((d) => d.encodedStructure)
          )
        }

        return map
      },
    })
  }

  public get version() {
    return this.structure.get('version')
  }

  public get documents() {
    return this.structure.get('documents')
  }

  public get documentErrors() {
    return this.structure.get('documentErrors')
  }

  public get status() {
    return this.structure.get('status')
  }

  public async verify(
    options: {
      deviceRequest?: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>
  ) {
    const onCheck = options.onCheck ?? defaultVerificationCallback

    const version = this.structure.get('version')
    onCheck({
      status: version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    const documents = this.structure.get('documents')
    onCheck({
      status: !documents || documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    for (const document of documents ?? []) {
      await document.deviceSigned.deviceAuth.verify(
        {
          document,
          ephemeralMacPrivateKey: options.ephemeralReaderKey,
          sessionTranscript: options.sessionTranscript,
          verificationCallback: onCheck,
        },
        ctx
      )

      await document.issuerSigned.verify(
        {
          verificationCallback: onCheck,
          disableCertificateChainValidation: options.disableCertificateChainValidation,
          now: options.now,
          trustedCertificates: options.trustedCertificates,
          skewSeconds: options.skewSeconds,
        },
        ctx
      )
    }

    if (options.deviceRequest?.docRequests && documents) {
      try {
        verifyDocRequestsWithIssuerSigned(
          options.deviceRequest.docRequests,
          documents.map((d) => d.issuerSigned)
        )
        onCheck({
          status: 'PASSED',
          check: 'Device Response did match the Device Request',
          category: 'DOCUMENT_FORMAT',
        })
      } catch (e) {
        onCheck({
          status: 'FAILED',
          check: `Device Response did not match the Device Request: ${(e as Error).message}`,
          category: 'DOCUMENT_FORMAT',
        })
      }
    }
  }

  public get encodedForOid4Vp() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vp(encoded: string): DeviceResponse {
    return DeviceResponse.decode(base64url.decode(encoded))
  }

  private static async create(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      signature?: {
        signingKey: CoseKey
      }
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const useMac = !!options.mac
    const useSignature = !!options.signature
    if (useMac === useSignature) throw new EitherSignatureOrMacMustBeProvidedError()

    const signingKey = useSignature ? options.signature?.signingKey : options.mac?.signingKey
    if (!signingKey) throw new Error('Signing key is missing')

    const documents = await Promise.all(
      options.deviceRequest.docRequests.map(async (docRequest) => {
        const issuerSigned = findIssuerSigned(options.issuerSigned, docRequest.itemsRequest.docType)
        const disclosedIssuerNamespace = limitDisclosureToDeviceRequestNameSpaces(issuerSigned, docRequest)

        const docType = docRequest.itemsRequest.docType

        const deviceNamespaces = options.deviceNamespaces ?? DeviceNamespaces.create({ deviceNamespaces: new Map() })

        const deviceAuthenticationBytes = DeviceAuthentication.create({
          sessionTranscript: options.sessionTranscript,
          docType,
          deviceNamespaces,
        }).encode({ asDataItem: true })

        const unprotectedHeaders = signingKey.keyId
          ? UnprotectedHeaders.create({ unprotectedHeaders: new Map([[Header.KeyId, signingKey.keyId]]) })
          : UnprotectedHeaders.create({})

        const protectedHeaders = ProtectedHeaders.create({
          protectedHeaders: new Map([[Header.Algorithm, signingKey.algorithm]]),
        })

        const deviceAuthOptions: DeviceAuthOptions = {}
        if (useSignature) {
          const deviceSignature = await DeviceSignature.create(
            {
              unprotectedHeaders,
              protectedHeaders,
              detachedPayload: deviceAuthenticationBytes,
              signingKey,
            },
            ctx
          )

          deviceAuthOptions.deviceSignature = deviceSignature
        } else {
          const ephemeralKey = options.mac?.ephemeralKey
          if (!ephemeralKey) throw new Error('Ephemeral key is missing')

          const deviceMac = await DeviceMac.create(
            {
              protectedHeaders,
              unprotectedHeaders,
              detachedPayload: deviceAuthenticationBytes,
              privateKey: signingKey,
              ephemeralKey: ephemeralKey,
              sessionTranscript: options.sessionTranscript,
            },
            ctx
          )

          deviceAuthOptions.deviceMac = deviceMac
        }

        return Document.create({
          docType,
          issuerSigned: IssuerSigned.create({
            issuerNamespaces: disclosedIssuerNamespace,
            issuerAuth: issuerSigned.issuerAuth,
          }),
          deviceSigned: DeviceSigned.create({
            deviceNamespaces,
            deviceAuth: DeviceAuth.create(deviceAuthOptions),
          }),
        })
      })
    )

    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', '1.0'],
      ['status', 0],
      ['documents', documents],
    ])

    return DeviceResponse.fromDecodedStructure(map)
  }

  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    return await DeviceResponse.create(options, ctx)
  }

  public static createSimple(options: DeviceResponseOptions): DeviceResponse {
    const map: DeviceResponseDecodedStructure = new TypedMap([
      ['version', options.version ?? '1.0'],
      ['status', options.status ?? 0],
    ])

    if (options.documents !== undefined) {
      map.set('documents', options.documents)
    }

    if (options.documentErrors !== undefined) {
      map.set('documentErrors', options.documentErrors)
    }

    return this.fromDecodedStructure(map)
  }
}
