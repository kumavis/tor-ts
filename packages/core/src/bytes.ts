// Byte-list primitives (verified core).
//
// Building blocks for the cell parser. Tor's link-cell wire format is
// position-dependent — a parser needs to take N bytes off the head of a
// buffer, read multi-byte integers in big-endian form, and pass the
// remainder to the next decoder. These helpers expose those operations
// over a structurally-recursive `ByteList`.
//
// `ByteList` is the verified-core stand-in for `Uint8Array` /
// `Buffer`. Each cell carries a `bigint` in the range `[0, 256)`. The
// TS-side seam adapter converts to/from real byte buffers at the
// boundary.
//
// Shape decisions:
//   * Multi-output operations return a discriminated union
//     (`SplitResult = { kind: 'ok'; taken; rest } | { kind: 'short' }`)
//     rather than a tuple, because Thales 0.5 emits tuples as Lean
//     `Array`s (issue 7 in docs/thales-issues.md).
//   * Inside `'ok'` branches we bind `sub.taken` / `sub.rest` to local
//     `const` variables before constructing a new DU, because Thales
//     emits `r.field` references that don't compile inside DU
//     constructor expressions (issue 8).

type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };

type SplitResult = { kind: 'ok'; taken: ByteList; rest: ByteList } | { kind: 'short' };

// ----------------------------------------------------------------------------
// Length
// ----------------------------------------------------------------------------

/** @total */
function byteListLength(bs: ByteList): bigint {
  switch (bs.kind) {
    case 'nil':
      return 0n;
    case 'cons':
      return 1n + byteListLength(bs.tail);
  }
}

// ----------------------------------------------------------------------------
// Concatenation
// ----------------------------------------------------------------------------

/** @total */
function byteListConcat(a: ByteList, b: ByteList): ByteList {
  switch (a.kind) {
    case 'nil':
      return b;
    case 'cons': {
      // Field access inside a DU ctor expression hits Thales issue 8;
      // bind to local consts first so the emitted Lean uses them.
      const aHead = a.head;
      const aTail = a.tail;
      return { kind: 'cons', head: aHead, tail: byteListConcat(aTail, b) };
    }
  }
}

// ----------------------------------------------------------------------------
// Take / drop / split
//
// `trySplit` is the workhorse: take exactly `n` bytes off the head and
// return the remainder, or fail (`'short'`) if the input is too short.
// Both `byteListTake` and `byteListDrop` are total versions that clamp
// rather than fail (returning what they have if `n` exceeds the
// length).
// ----------------------------------------------------------------------------

/**
 * Helper that lifts a successful sub-split through one cons cell.
 * Extracted to a separate function so that constructing the new
 * `'ok'` value happens after the field accesses (issue 8 workaround).
 */
/** @total */
function consIntoSplit(head: bigint, sub: SplitResult): SplitResult {
  switch (sub.kind) {
    case 'short':
      return { kind: 'short' };
    case 'ok': {
      const subTaken = sub.taken;
      const subRest = sub.rest;
      return {
        kind: 'ok',
        taken: { kind: 'cons', head, tail: subTaken },
        rest: subRest,
      };
    }
  }
}

/**
 * Take exactly `n` bytes off the head of `bs`. Returns `{ taken, rest }`
 * on success, or `{ short }` if `bs` has fewer than `n` bytes.
 */
/** @total */
function trySplit(n: bigint, bs: ByteList): SplitResult {
  if (n <= 0n) {
    return { kind: 'ok', taken: { kind: 'nil' }, rest: bs };
  }
  switch (bs.kind) {
    case 'nil':
      return { kind: 'short' };
    case 'cons':
      return consIntoSplit(bs.head, trySplit(n - 1n, bs.tail));
  }
}

// ----------------------------------------------------------------------------
// Big-endian unsigned-integer decode
//
// Reads every byte of `bs` left-to-right as a base-256 numeral. The
// caller is responsible for slicing the byte list to the desired width
// (e.g. via `trySplit`) before calling.
// ----------------------------------------------------------------------------

/** @total */
function bigEndianUintAux(acc: bigint, bs: ByteList): bigint {
  switch (bs.kind) {
    case 'nil':
      return acc;
    case 'cons':
      return bigEndianUintAux(acc * 256n + bs.head, bs.tail);
  }
}

/** @total */
function bigEndianUint(bs: ByteList): bigint {
  return bigEndianUintAux(0n, bs);
}

// ----------------------------------------------------------------------------
// Little-endian unsigned-integer codec
//
// In LE form the first byte of the list is the least-significant byte:
//
//     [b0, b1, b2, ...] = b0 + 256·b1 + 256²·b2 + ...
//
// Mirrors `bytesToBigIntLE` and `bigIntToBytesLE` from
// `packages/crypto/src/hs-crypto.ts`, used in the curve25519/ed25519
// scalar conversions for hidden-service key derivation.
// ----------------------------------------------------------------------------

/**
 * Decode a `ByteList` as a little-endian unsigned bigint. Recurses
 * structurally on the list (which is what makes this `@total`).
 */
/** @total */
function bytesToBigIntLE(bs: ByteList): bigint {
  switch (bs.kind) {
    case 'nil':
      return 0n;
    case 'cons':
      return bs.head + 256n * bytesToBigIntLE(bs.tail);
  }
}

// Note: a `bigIntToBytesLE(n, length)` encoder is the natural inverse,
// but it recurses on `length` (an `Int`) which neither structural
// recursion nor Thales 0.5's `@decreasing` annotation handle yet.
// Lean rejects the resulting `partial def` because `ByteList` doesn't
// auto-derive `Nonempty`. Once Thales 0.5+ either honours
// `@decreasing` or emits `deriving Nonempty` for inductives, the
// encoder can land here and the round-trip theorem
// `bytesToBigIntLE (bigIntToBytesLE n l) = n mod 256^l` becomes
// reachable.
