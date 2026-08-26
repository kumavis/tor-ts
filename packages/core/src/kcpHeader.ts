// KCP header field decoders (verified core).
//
// The KCP segment header (xtaci/kcp-go and skywind3000/kcp wire
// format) is 24 bytes of little-endian integers:
//
//   0:4  conv (uint32)
//   4:5  cmd  (uint8)
//   5:6  frg  (uint8)
//   6:8  wnd  (uint16)
//   8:12 ts   (uint32)
//   12:16 sn  (uint32)
//   16:20 una (uint32)
//   20:24 len (uint32)
//   24:   data
//
// The full segment decoder lives in
// `packages/snowflake/src/kcp/segment.ts`. This module provides the
// integer-decode primitives that the segment decoder needs but
// `bytes.ts` doesn't yet have (BE decoders only). LE differs from BE
// in byte order: the *first* byte is the least-significant.
//
// Re-declares the byte-list primitives from `bytes.ts` because Thales
// 0.5 has no `import` (Issue 5 in docs/thales-issues.md). When that
// lands these duplicates come out and `kcpHeader.ts` imports from
// `bytes.ts`.

// ----------------------------------------------------------------------------
// (Mirrored from bytes.ts — keep in sync)
// ----------------------------------------------------------------------------

type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };

type SplitResult = { kind: 'ok'; taken: ByteList; rest: ByteList } | { kind: 'short' };

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

// ----------------------------------------------------------------------------
// LE-uint decoders.
//
// Same shape as parseLengthPrefix in cellHeader.ts: split off N bytes
// and decode them. Failure (`'short'`) propagates from the split.
// ----------------------------------------------------------------------------

type ParseUintLEResult = { kind: 'ok'; value: bigint; rest: ByteList } | { kind: 'short' };

/** @total */
function decodeUintLEFromSplit(sub: SplitResult): ParseUintLEResult {
  switch (sub.kind) {
    case 'short':
      return { kind: 'short' };
    case 'ok': {
      const subTaken = sub.taken;
      const subRest = sub.rest;
      return {
        kind: 'ok',
        value: bytesToBigIntLE(subTaken),
        rest: subRest,
      };
    }
  }
}

/**
 * Read an 8-bit unsigned integer (single byte) off the head of `bs`.
 * Used for KCP `cmd` and `frg`.
 */
/** @total */
function decodeUint8LE(bs: ByteList): ParseUintLEResult {
  return decodeUintLEFromSplit(trySplit(1n, bs));
}

/**
 * Read a 16-bit little-endian unsigned integer off the head of `bs`.
 * Used for KCP `wnd`.
 */
/** @total */
function decodeUint16LE(bs: ByteList): ParseUintLEResult {
  return decodeUintLEFromSplit(trySplit(2n, bs));
}

/**
 * Read a 32-bit little-endian unsigned integer off the head of `bs`.
 * Used for KCP `conv`, `ts`, `sn`, `una`, `len`.
 */
/** @total */
function decodeUint32LE(bs: ByteList): ParseUintLEResult {
  return decodeUintLEFromSplit(trySplit(4n, bs));
}
