// biome-ignore format: no explanation
export class MdlError extends Error {
  constructor(message: string = new.target.name) {
    super(message)
  }
}

export class MdlParseError extends MdlError {}
export class PresentationDefinitionOrDocRequestsAreRequiredError extends MdlError {}
export class SessionTranscriptOrSessionTranscriptBytesAreRequiredError extends MdlError {}
export class DuplicateNamespaceInIssuerNamespacesError extends MdlError {}
export class DuplicateDocumentInDeviceResponseError extends MdlError {}
export class EitherSignatureOrMacMustBeProvidedError extends MdlError {}
export class AtLeastOneCertificateRequiredError extends MdlError {}
