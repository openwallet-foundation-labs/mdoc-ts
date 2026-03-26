import { z } from 'zod'
import type zCore from 'zod/v4/core'

/**
 * TypedMap provides compile-time type safety for Maps where each key has its own specific value type.
 * Unlike Map<K, V> which has the same value type V for all keys, TypedMap<Schema, OptionalKeys>
 * allows different value types per key (heterogeneous values).
 *
 * Example:
 *   type CoseKeySchema = {
 *     [CoseKeyParameter.KeyType]: KeyType     // number key → KeyType value
 *     [CoseKeyParameter.Curve]: Curve         // number key → Curve value
 *     [CoseKeyParameter.X]: Uint8Array        // number key → Uint8Array value
 *   }
 *
 *   const map = new TypedMap<CoseKeySchema>()
 *   map.get(CoseKeyParameter.KeyType)  // TypeScript knows this is KeyType!
 *   map.get(CoseKeyParameter.Curve)    // TypeScript knows this is Curve!
 *   map.get(CoseKeyParameter.X)        // TypeScript knows this is Uint8Array!
 *
 * @template Schema - Object type mapping keys to their value types
 * @template OptionalKeys - Union of keys that are optional (can be absent)
 */

// biome-ignore lint/suspicious/noExplicitAny: no explanation
export class TypedMap<Schema extends Record<PropertyKey, any>, OptionalKeys extends keyof Schema = never> {
  private readonly map: Map<keyof Schema, Schema[keyof Schema]>

  constructor(entries?: (readonly [keyof Schema, Schema[keyof Schema]])[] | null) {
    this.map = new Map(entries)
  }

  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  public static fromMap<Schema extends Record<PropertyKey, any>, OptionalKeys extends keyof Schema = never>(
    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    map: Map<any, any>
  ) {
    return new TypedMap<Schema, OptionalKeys>(Array.from(map.entries()))
  }

  /**
   * Type-safe get that returns the correct value type for each key.
   * Required keys return T, optional keys return T | undefined.
   */
  get<K extends keyof Schema>(key: K): K extends OptionalKeys ? Schema[K] | undefined : Schema[K] {
    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    return this.map.get(key) as any
  }

  /**
   * Type-safe set that ensures the value matches the key's type
   */
  set<K extends keyof Schema>(key: K, value: Schema[K]): this {
    this.map.set(key, value)
    return this
  }

  has(key: keyof Schema): boolean {
    return this.map.has(key)
  }

  delete(key: keyof Schema): boolean {
    return this.map.delete(key)
  }

  clear(): void {
    this.map.clear()
  }

  get size(): number {
    return this.map.size
  }

  keys(): IterableIterator<keyof Schema> {
    return this.map.keys()
  }

  values(): IterableIterator<Schema[keyof Schema]> {
    return this.map.values()
  }

  entries(): IterableIterator<[keyof Schema, Schema[keyof Schema]]> {
    return this.map.entries()
  }

  forEach(
    callbackfn: (value: Schema[keyof Schema], key: keyof Schema, map: Map<keyof Schema, Schema[keyof Schema]>) => void,
    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    thisArg?: any
  ): void {
    this.map.forEach(callbackfn, thisArg)
  }

  [Symbol.iterator](): IterableIterator<[keyof Schema, Schema[keyof Schema]]> {
    return this.map[Symbol.iterator]()
  }

  toMap(): Map<keyof Schema, Schema[keyof Schema]> {
    return new Map(this.map)
  }
}

// Helper type to build schema from entries array
// biome-ignore lint/suspicious/noExplicitAny: no explanation
type EntriesArrayToSchema<T extends ReadonlyArray<readonly [any, any]>> = {
  // biome-ignore lint/suspicious/noExplicitAny: no explanation
  [K in T[number][0]]: Extract<T[number], readonly [K, any]>[1]
}

/**
 * This checks whether the property is exact optional. exact optional means that the value cannot be undefined, but if used
 * in an object the key can be omitted. This is important for CBOR structures, as undefined will be encoded, and thus must be
 * omitted in most cases.
 *
 * Zod recommend to check for optionality by just parsing undefined.
 */
const isExactOptional = (schema: z.ZodType) =>
  !schema.safeParse(undefined).success && z.object({ test: schema }).safeParse({}).success

type EntriesBase = ReadonlyArray<
  readonly [
    string | number, // for now we only allow string or number keys
    // biome-ignore lint/suspicious/noExplicitAny: no explanation
    z.ZodType<any>,
  ]
>

type InferredEntries<Entries extends EntriesBase> = {
  [K in keyof Entries]: readonly [Entries[K][0], z.infer<Entries[K][1]>]
}
type InferredSchema<Entries extends EntriesBase> = EntriesArrayToSchema<InferredEntries<Entries>>

type OptionalKeys<Entries extends EntriesBase> = Entries[number] extends infer E
  ? E extends readonly [infer K, infer V]
    ? // biome-ignore lint/suspicious/noExplicitAny: no explanation
      V extends z.ZodExactOptional<any>
      ? K
      : never
    : never
  : never

/**
 * Utility function to create a typed map codec.
 * Takes an array of [key, valueSchema] entries to support any key type (including non-string keys for CBOR).
 *
 * Example:
 *   const coseKeyMap = typedMap([
 *     [CoseKeyParameter.KeyType, z.number()],
 *     [CoseKeyParameter.Curve, z.number()],
 *     [CoseKeyParameter.X, z.instanceof(Uint8Array)]
 *   ] as const)
 *
 * The resulting schema validates a Map and transforms it to TypedMap<Schema, never>.
 */
export function typedMap<const Entries extends EntriesBase>(
  entries: Entries,
  {
    allowAdditionalKeys = true,
    encode,
    decode,
  }: {
    /**
     * Whether to allow additional keys in the typed map
     *
     * @default true
     */
    allowAdditionalKeys?: boolean

    /**
     * Allows overriding the encode function. The original encode method is passed as second
     * argument, so you can use this method to pre/post process
     */
    encode?: (
      decoded: TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>,
      originalEncode: (decoded: TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>) => Map<unknown, unknown>
    ) => Map<unknown, unknown>

    /**
     * Allows overriding the decode function. The original decode method is passed as second
     * argument, so you can use this method to pre/post process
     */
    decode?: (
      encoded: Map<unknown, unknown>,
      originalDecode: (decoded: Map<unknown, unknown>) => TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>
    ) => TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>
  } = {}
) {
  // Create a set of required keys (non-optional) for validation
  const requiredKeys = entries.filter(([, valueSchema]) => !isExactOptional(valueSchema)).map(([key]) => key)

  const schemaMap = new Map(entries)

  const originalEncode = (decoded: TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>) => decoded.toMap()
  const originalDecode = (encoded: Map<unknown, unknown>) =>
    TypedMap.fromMap<InferredSchema<Entries>, OptionalKeys<Entries>>(encoded)

  return z.codec(
    // Input is untyped map
    z.map(z.unknown(), z.unknown()),
    // Output is typed map
    z.instanceof<typeof TypedMap<InferredSchema<Entries>, OptionalKeys<Entries>>>(TypedMap).superRefine((map, ctx) => {
      // Check there's no additional keys in the map if not allowed
      const additionalKeys = Array.from(map.keys()).filter((key) => !schemaMap.has(key as string | number))
      if (additionalKeys.length > 0 && !allowAdditionalKeys) {
        for (const additionalKey of additionalKeys) {
          if (typeof additionalKey !== 'string' && typeof additionalKey !== 'number') {
            ctx.addIssue({
              code: 'invalid_key',
              origin: 'map',
              continue: true,
              path: [],
              input: map,
              issues: [],
              message: 'Key found in map that is not a string or number',
            })
          } else {
            ctx.addIssue({
              code: 'invalid_key',
              origin: 'map',
              continue: true,
              path: [additionalKey],
              input: map,
              issues: [],
              message: `Unexpected key '${additionalKey}' found in map, additional keys are not allowed.`,
            })
          }
        }
      }

      for (const [key, valueSchema] of schemaMap.entries()) {
        const hasKey = map.has(key)
        const value = map.get(key)

        if (!hasKey && requiredKeys.includes(key)) {
          ctx.addIssue({
            code: 'invalid_value',
            continue: true,
            message: `Expected key '${key}' to be defined.`,
            path: [key],
            values: [],
            input: value,
          })
          continue
        }

        // If key is not in the map, and also not required, skip validation
        if (!hasKey && !requiredKeys.includes(key)) {
          continue
        }

        const parseResult = valueSchema.safeParse(value)
        if (!parseResult.success) {
          for (const issue of parseResult.error.issues) {
            ctx.addIssue({
              ...issue,
              // NOTE: if we use numbers, zod-validation-error will use "index", thinking
              // it's an array, that's confusing
              path: [`${key}`, ...issue.path],
            } as zCore.$ZodSuperRefineIssue)
          }
        }
      }
    }),
    {
      decode: (input) => (decode ? decode(input, originalDecode) : originalDecode(input)),
      encode: (output) => (encode ? encode(output, originalEncode) : originalEncode(output)),
    }
  )
}
