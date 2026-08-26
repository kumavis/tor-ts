// Byte encoders (verified core) — the inverses of the decoders in
// `bytes.ts` and `kcpHeader.ts`.
//
// Every decoder in core used to have no inverse, so the strongest thing
// we could say about the wire format was a per-direction invariant.
// With encoders we can state the real property:
//
//     decode (encode v w) = v          -- for v in range
//     trySplit (encode v w ++ rest)    -- recovers v and rest exactly
//
// which is what `Spec/ByteEncode.lean` proves.
//
// ---------------------------------------------------------------------
// Why widths are unary
// ---------------------------------------------------------------------
//
// The obvious signature is `encodeUintLE(value: bigint, width: bigint)`,
// recursing on `width - 1n`. That is not a *structural* decrease, so
// Lean's termination checker rejects it and `@total` fails — the same
// wall `bytes.ts` hit (see its closing note) and exactly the case
// `subset.md` calls out under "Typical patterns that fail with @total":
// integer arithmetic decrease on `bigint` has no structural decrease.
//
// So the width is a unary Peano-style DU instead. Recursion on `Width`
// *is* structural, so every encoder here is `@total`, and the round-trip
// proofs get a clean induction principle for free. Tor's field widths
// are tiny fixed constants (1, 2, 4 bytes), so the unary encoding costs
// nothing in practice — `width4()` is four constructors deep.
//
// Re-declares the byte-list primitives from `bytes.ts` because an
// exported discriminated union cannot be pattern-matched downstream
// (MIGRATION.md F3 / thales-issues.md #14). When that lands, these
// duplicates come out.

type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };

type SplitResult = { kind: 'ok'; taken: ByteList; rest: ByteList } | { kind: 'short' };

/** A width in bytes, as a unary numeral. See the header note. */
type Width = { kind: 'zero' } | { kind: 'succ'; pred: Width };

// ----------------------------------------------------------------------------
// (Mirrored from bytes.ts — keep in sync)
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

/** @total */
function byteListConcat(a: ByteList, b: ByteList): ByteList {
  switch (a.kind) {
    case 'nil':
      return b;
    case 'cons': {
      const aHead = a.head;
      const aTail = a.tail;
      return { kind: 'cons', head: aHead, tail: byteListConcat(aTail, b) };
    }
  }
}

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

/** @total */
function bytesToBigIntLE(bs: ByteList): bigint {
  switch (bs.kind) {
    case 'nil':
      return 0n;
    case 'cons':
      return bs.head + 256n * bytesToBigIntLE(bs.tail);
  }
}

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

/**
 * Truncated remainder — the value `a % b` would have.
 *
 * Written without `%` because Thales lowers `%` on `bigint` to the Float
 * helper `jsMod`, which produces uncompilable Lean (MIGRATION.md F2 /
 * thales-issues.md #13). Both TS `bigint /` and Lean `Int./` truncate
 * toward zero, so `a - (a / b) * b` is exactly the truncated remainder
 * on both paths.
 */
/** @total */
function truncMod(a: bigint, b: bigint): bigint {
  return a - (a / b) * b;
}

// ----------------------------------------------------------------------------
// Width arithmetic
// ----------------------------------------------------------------------------

/** The width as an ordinary integer: the number of bytes emitted. */
/** @total */
function widthValue(w: Width): bigint {
  switch (w.kind) {
    case 'zero':
      return 0n;
    case 'succ':
      return 1n + widthValue(w.pred);
  }
}

/**
 * `256 ^ widthValue(w)` — the number of distinct values a `w`-byte field
 * can hold. A value is encodable at width `w` exactly when it lies in
 * `[0, capacity(w))`.
 */
/** @total */
function capacity(w: Width): bigint {
  switch (w.kind) {
    case 'zero':
      return 1n;
    case 'succ':
      return 256n * capacity(w.pred);
  }
}

/** @total */
function succWidth(w: Width): Width {
  return { kind: 'succ', pred: w };
}

/** Width 0 — encodes nothing. */
/** @total */
function width0(): Width {
  return { kind: 'zero' };
}

/** Width 1: KCP `cmd`/`frg`, Tor's command byte. */
/** @total */
function width1(): Width {
  return succWidth(width0());
}

/** Width 2: KCP `wnd`, Tor's circuit ID (link v4+) and length prefix. */
/** @total */
function width2(): Width {
  return succWidth(width1());
}

/** Width 4: KCP `conv`/`ts`/`sn`/`una`/`len`. */
/** @total */
function width4(): Width {
  return succWidth(succWidth(width2()));
}

// ----------------------------------------------------------------------------
// Encoders
//
// Both emit exactly `widthValue(w)` bytes, and both encode the value
// modulo `capacity(w)` — a value too large for the field is truncated,
// not rejected, matching what the TS-side writers do with
// `writeUIntBE`/`writeUIntLE` on an oversized value.
// ----------------------------------------------------------------------------

/**
 * Encode `value` as `w` little-endian bytes: least-significant byte
 * first. The inverse of `bytesToBigIntLE`, and of the `decodeUint*LE`
 * family in `kcpHeader.ts`.
 */
/** @total */
function encodeUintLE(value: bigint, w: Width): ByteList {
  switch (w.kind) {
    case 'zero':
      return { kind: 'nil' };
    case 'succ': {
      // Bind before the DU constructor (thales-issues.md #8).
      const pred = w.pred;
      const lo = truncMod(value, 256n);
      const hi = value / 256n;
      return { kind: 'cons', head: lo, tail: encodeUintLE(hi, pred) };
    }
  }
}

/**
 * Encode `value` as `w` big-endian bytes: most-significant byte first.
 * The inverse of `bigEndianUint`, and so of `parseCircId` /
 * `parseLengthPrefix` in `cellHeader.ts`.
 *
 * Recurses on the width the same way `encodeUintLE` does, appending the
 * low byte at the *end* rather than consing it at the front.
 */
/** @total */
function encodeUintBE(value: bigint, w: Width): ByteList {
  switch (w.kind) {
    case 'zero':
      return { kind: 'nil' };
    case 'succ': {
      const pred = w.pred;
      const lo = truncMod(value, 256n);
      const hi = value / 256n;
      const lastByte: ByteList = { kind: 'cons', head: lo, tail: { kind: 'nil' } };
      return byteListConcat(encodeUintBE(hi, pred), lastByte);
    }
  }
}

// ----------------------------------------------------------------------------
// Named field encoders
//
// The widths Tor and KCP actually use, so callers never build a `Width`
// by hand.
// ----------------------------------------------------------------------------

/** @total */
function encodeUint8(value: bigint): ByteList {
  return encodeUintLE(value, width1());
}

/** @total */
function encodeUint16BE(value: bigint): ByteList {
  return encodeUintBE(value, width2());
}

/** @total */
function encodeUint32BE(value: bigint): ByteList {
  return encodeUintBE(value, width4());
}

/** @total */
function encodeUint16LE(value: bigint): ByteList {
  return encodeUintLE(value, width2());
}

/** @total */
function encodeUint32LE(value: bigint): ByteList {
  return encodeUintLE(value, width4());
}

/**
 * Serialize a circuit ID at the width the link protocol version calls
 * for: 2 bytes for link versions 1–3, 4 bytes for 4 and up. The inverse
 * of `parseCircId` in `cellHeader.ts`; `circIdLengthForVersion` there is
 * the same version split.
 */
/** @total */
function serializeCircId(linkVersion: bigint, circId: bigint): ByteList {
  if (linkVersion >= 4n) {
    return encodeUintBE(circId, width4());
  }
  return encodeUintBE(circId, width2());
}
