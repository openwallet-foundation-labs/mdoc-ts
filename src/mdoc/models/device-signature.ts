import { Sign1, type Sign1DecodedStructure, type Sign1EncodedStructure, type Sign1Options } from '@owf/cose'

export type DeviceSignatureEncodedStructure = Sign1EncodedStructure
export type DeviceSignatureDecodedStructure = Sign1DecodedStructure
export type DeviceSignatureOptions = Sign1Options

export class DeviceSignature extends Sign1 {}
