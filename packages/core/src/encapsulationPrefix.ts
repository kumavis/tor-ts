// Snowflake encapsulation length-prefix decoder (verified core).
//
// Snowflake's "encapsulation" framing
// (gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/encapsulation)
// prefixes each chunk with a 1- to 3-byte variable-length header.
//
// First byte:
//   bit 7 (0x80): isData (1 = data chunk, 0 = padding)
//   bit 6 (0x40): more   (1 = another length byte follows)
//   bits 5..0:    low 6 bits of length
//
// Continuation bytes (up to 2):
//   bit 7 (0x80): more
//   bits 6..0:    next 7 bits of length (MSB-first)
//
// So the encoded length is 6 bits in 1 header byte, 13 bits in 2,
// or 20 bits (max 0xfffff = 1048575) in 3. A 4th byte's worth of
// continuation is rejected as "too long".
//
// Mirrors `EncapsulationDecoder.tryReadLengthPrefix` in
// `packages/snowflake/src/encapsulation.ts`. The full streaming
// decoder needs the byte-list primitives composed across modules
// (Issue 5), so this slice covers the prefix decode in isolation.
//
// Re-declares the byte-list type from `bytes.ts` because Thales 0.5
// has no `import`.

type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };

type ParsePrefixResult =
  | {
      kind: 'ok';
      isData: boolean;
      length: bigint;
      headerBytes: bigint;
      rest: ByteList;
    }
  | { kind: 'short' }
  | { kind: 'too_long' };

// ----------------------------------------------------------------------------
// Bit-extraction helpers.
//
// Arithmetic only — Thales does not lower bitwise operators on `bigint`,
// so masks are expressed as remainders and shifts as multiplications.
// ----------------------------------------------------------------------------

/**
 * Truncated remainder — the value `a % b` would have.
 *
 * Written without `%` because Thales 0.7 lowers `%` on `bigint` to the
 * Float helper `jsMod`, which produces uncompilable Lean (see
 * MIGRATION.md F2 / thales-issues.md #13). Both TS `bigint /` and Lean
 * `Int./` truncate toward zero, so `a - (a / b) * b` is exactly the
 * truncated remainder on both paths.
 */
/** @total */
function truncMod(a: bigint, b: bigint): bigint {
  return a - (a / b) * b;
}

/** Whether the high bit (0x80) of a byte is set. Assumes 0 ≤ b < 256. */
/** @total */
function highBitSet(b: bigint): boolean {
  return b >= 128n;
}

/** The low 7 bits (0x7f) of a byte. */
/** @total */
function low7Bits(b: bigint): bigint {
  return truncMod(b, 128n);
}

/** Whether the second-highest bit (0x40) of a byte is set, given the
    byte. Equivalent to `(b mod 128) >= 64`. */
/** @total */
function secondHighBitSet(b: bigint): boolean {
  return truncMod(b, 128n) >= 64n;
}

/** The low 6 bits (0x3f) of a byte. */
/** @total */
function low6Bits(b: bigint): bigint {
  return truncMod(b, 64n);
}

// ----------------------------------------------------------------------------
// Continuation: structural recursion on `remaining`. We've consumed the
// first header byte and are reading additional 7-bit length pieces, up
// to `maxAdditional` more bytes (starts at 2 since the first byte
// already used 1 of the 3-byte budget).
// ----------------------------------------------------------------------------

/** @total */
function continuePrefix(
  isData: boolean,
  acc: bigint,
  headerBytes: bigint,
  remaining: ByteList,
  maxAdditional: bigint
): ParsePrefixResult {
  if (maxAdditional <= 0n) {
    return { kind: 'too_long' };
  }
  switch (remaining.kind) {
    case 'nil':
      return { kind: 'short' };
    case 'cons': {
      const b = remaining.head;
      const tail = remaining.tail;
      const more = highBitSet(b);
      const piece = low7Bits(b);
      const newAcc = acc * 128n + piece;
      const newHeaderBytes = headerBytes + 1n;
      if (more) {
        return continuePrefix(isData, newAcc, newHeaderBytes, tail, maxAdditional - 1n);
      }
      return {
        kind: 'ok',
        isData,
        length: newAcc,
        headerBytes: newHeaderBytes,
        rest: tail,
      };
    }
  }
}

// ----------------------------------------------------------------------------
// Top-level parser. Reads the first header byte, dispatches on whether
// the `more` bit is set.
// ----------------------------------------------------------------------------

/**
 * Decode a 1- to 3-byte encapsulation length prefix off the head of
 * `bs`. Returns:
 *
 *   - `'ok'` with the decoded `isData` flag, the `length` field, the
 *     number of header bytes consumed, and the remaining input.
 *   - `'short'` if the input doesn't have enough bytes for the
 *     announced multi-byte prefix.
 *   - `'too_long'` if the prefix would extend past 3 bytes (a
 *     malformed input that the spec rejects).
 */
/** @total */
function parseEncapsulationPrefix(bs: ByteList): ParsePrefixResult {
  switch (bs.kind) {
    case 'nil':
      return { kind: 'short' };
    case 'cons': {
      const b = bs.head;
      const tail = bs.tail;
      const isData = highBitSet(b);
      const more = secondHighBitSet(b);
      const initial = low6Bits(b);
      if (more) {
        return continuePrefix(isData, initial, 1n, tail, 2n);
      }
      return {
        kind: 'ok',
        isData,
        length: initial,
        headerBytes: 1n,
        rest: tail,
      };
    }
  }
}
