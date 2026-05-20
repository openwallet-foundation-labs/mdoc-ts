import { CoseKey, type CoseKeyDecodedStructure, type CoseKeyEncodedStructure, type CoseKeyOptions } from '@owf/cose'

export type DeviceKeyDecodedStructure = CoseKeyDecodedStructure
export type DeviceKeyEncodedStructure = CoseKeyEncodedStructure
export type DeviceKeyOptions = CoseKeyOptions

// DeviceKey is just a CoseKey with a different name/type for clarity in mdoc context
export class DeviceKey extends CoseKey {}
