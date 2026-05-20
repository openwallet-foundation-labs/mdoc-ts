import { CoseKey, type CoseKeyDecodedStructure, type CoseKeyEncodedStructure, type CoseKeyOptions } from '@owf/cose'

export type EDeviceKeyDecodedStructure = CoseKeyDecodedStructure
export type EDeviceKeyEncodedStructure = CoseKeyEncodedStructure
export type EDeviceKeyOptions = CoseKeyOptions

export class EDeviceKey extends CoseKey {}
