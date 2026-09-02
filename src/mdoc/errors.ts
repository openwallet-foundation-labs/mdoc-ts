// biome-ignore format: no explanation
export class MdlError extends Error {
  constructor(message: string = new.target.name) {
    super(message)
  }
}

export class MdlParseError extends MdlError {}
export class EitherSignatureOrMacMustBeProvidedError extends MdlError {}
export class AtLeastOneCertificateRequiredError extends MdlError {}
export class SignatureAlgorithmDoesNotMatchSigningKeyAlgorithmError extends MdlError {}
export class UnableToExtractX5ChainFromCwtError extends MdlError {}
export class NoPublicKeySetOnStatusListError extends MdlError {}
export class InvalidSignatureError extends MdlError {}

/**
 * ISO/IEC 18013-5 second edition § 12.3.6.3 requires the status list of an MSO to be a Status List
 * Token in CWT format, "since the IssuerAuth structure is a CWT". A list served as a JWT is a
 * deviation, and is rejected rather than verified.
 */
export class JwtNotSupportForStatusListError extends MdlError {}
export class TrustedRevocationCertificatesMustContainAtleastOneCertificateError extends MdlError {}
export class UnableToExtractX5ChainFromIdentifierListError extends MdlError {}
export class InvalidIdentifierListSignatureError extends MdlError {}
export class IdentifierFoundInRevokedListError extends MdlError {}

/**
 * An MSO revocation list — status list or identifier list — was well-formed and correctly
 * signed, but one of the claim requirements from ISO/IEC 18013-5 second edition 12.3.6 /
 * the Token Status List specification was not met (missing or mismatched subject, missing
 * or passed expiration, or an issuance time in the future).
 */
export class InvalidRevocationListError extends MdlError {}

/**
 * ISO/IEC TS 18013-7:2025 C.5 requires the mdoc to abort when the DC API did not provide an origin,
 * as the session transcript — and thus the anti-relay binding — cannot be computed without it.
 */
export class MissingOriginError extends MdlError {}
export class HpkeNotSupportedError extends MdlError {}

/**
 * The request or response payload handed over the DC API did not have the shape Annex C defines.
 */
export class InvalidDcApiRequestError extends MdlError {}
export class InvalidDcApiResponseError extends MdlError {}
export class InvalidEncryptionInfoError extends MdlError {}
export class InvalidEncryptedResponseError extends MdlError {}
