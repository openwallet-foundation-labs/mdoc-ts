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
export class SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError extends MdlError {}
export class UnableToExtractX5ChainFromCwtError extends MdlError {}
export class NoPublicKeySetOnStatusListError extends MdlError {}
export class InvalidAlgorithmError extends MdlError {}
export class InvalidMessageAuthenticationCode extends MdlError {}
export class InvalidSignatureError extends MdlError {}
export class JwtNotSupportForStatusListError extends MdlError {}
export class TrustedRevocationCertificatesMustContainAtleastOneCertificateError extends MdlError {}
export class NoGetTrustedStatusCertificatesDefinedError extends MdlError {}
