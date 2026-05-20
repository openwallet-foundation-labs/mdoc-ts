import { CoseKey, type CoseKeyDecodedStructure, type CoseKeyEncodedStructure, type CoseKeyOptions } from '@owf/cose'

export type EReaderKeyDecodedStructure = CoseKeyDecodedStructure
export type EReaderKeyEncodedStructure = CoseKeyEncodedStructure
export type EReaderKeyOptions = CoseKeyOptions

// EReaderKey is just a CoseKey with a different name/type for clarity in mdoc context
export class EReaderKey extends CoseKey {}
