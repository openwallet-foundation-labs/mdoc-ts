import type { DocType } from '../mdoc/models/doctype'
import type { IssuerSigned } from '../mdoc/models/issuer-signed'

export const findIssuerSigned = (is: Array<IssuerSigned>, docType: DocType) => {
  const issuerSigned = is.filter((i) => i.issuerAuth.mobileSecurityObject.docType === docType)

  if (!issuerSigned?.[0]) {
    throw new Error(`No Issuer Signed matching docType '${docType}'`)
  }

  if (issuerSigned.length > 1) {
    throw new Error(`Multiple Issuer Signed matching docType '${docType}'`)
  }

  return issuerSigned[0]
}
