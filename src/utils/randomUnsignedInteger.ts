import type { MdocContext } from '../context'

export const randomUnsignedInteger = (ctx: Pick<MdocContext, 'crypto'>) => {
  const bytes = ctx.crypto.random(4)
  // ISO/IEC 18013-5 §12.3.4 mandates DigestID values smaller than 2^31. We mask
  // off the most significant bit so the result stays in [0, 2^31 - 1] while
  // preserving the full 31 bits of entropy.
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) & 0x7fffffff
}
