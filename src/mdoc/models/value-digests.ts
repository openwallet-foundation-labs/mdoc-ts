import { CborStructure } from '@owf/cose'
import { z } from 'zod'
import { zUint8Array } from '../../utils/zod'
import type { DigestId } from './digest-id'
import type { Namespace } from './namespace'

// ValueDigests: Map<Namespace, Map<DigestId, Digest>>
// Using nested Maps because DigestId is a number (integer key)
// Maps with integer keys always stay as Maps, even when parent uses mapsAsObjects: true

// Zod codec for ValueDigests
// When parent uses mapsAsObjects: true, ALL maps become objects (even with integer keys!)
const valueDigestsSchema = z.map(z.string(), z.map(z.number(), zUint8Array))

export type ValueDigestsStructure = z.infer<typeof valueDigestsSchema>

export type ValueDigestOptions = {
  digests: ValueDigestsStructure
}

export class ValueDigests extends CborStructure<ValueDigestsStructure> {
  public static override get encodingSchema() {
    return valueDigestsSchema
  }

  public get valueDigests() {
    return this.structure
  }

  public static create(options: ValueDigestOptions) {
    return this.fromEncodedStructure(options.digests)
  }

  public getDigestForNamespace(namespace: Namespace, digestId: DigestId) {
    return this.structure.get(namespace)?.get(digestId)
  }

  public hasDigestForNamespace(namespace: Namespace, digestId: DigestId) {
    return this.structure.get(namespace)?.has(digestId) ?? false
  }

  public getNamespaces(): Namespace[] {
    return Array.from(this.structure.keys())
  }

  public getDigestIdsForNamespace(namespace: Namespace): DigestId[] {
    const namespaceDigests = this.structure.get(namespace)
    if (!namespaceDigests) {
      return []
    }
    return Array.from(namespaceDigests.keys())
  }
}
