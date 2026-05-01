// Tor link-cell header parsing (verified core).
//
// The first field of every Tor link-layer cell is a circuit ID, whose
// width is link-version-dependent: 2 bytes on link versions 1–3,
// 4 bytes on link versions 4 and above (tor-spec.txt §4 and §5).
// `parseCircId` extracts it from the head of a byte stream.
//
// This module currently re-declares the byte-list primitives from
// `bytes.ts` because Thales 0.5's parser does not accept `import` /
// `export` (issue 5 in docs/thales-issues.md). When that lands the
// duplicates come out and `cellHeader.ts` can depend on `bytes.ts`
// directly. Until then, the two declarations have to be kept in sync
// by hand — there is a same-shape comment on each side.

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
// Circuit-ID parsing.
//
// On link version v, circIds are encoded as `circIdLengthForVersion(v)`
// bytes in big-endian byte order at the head of every cell. Versions
// 1–3 use 2 bytes; version 4 introduced 4-byte circIds (tor-spec.txt
// §5.1.1).
// ----------------------------------------------------------------------------

/** @total */
function circIdLengthForVersion(linkVersion: bigint): bigint {
  if (linkVersion < 4n) {
    return 2n;
  }
  return 4n;
}

type ParseCircIdResult = { kind: 'ok'; circId: bigint; rest: ByteList } | { kind: 'short' };

/**
 * Lift the result of a successful split into a ParseCircIdResult,
 * decoding the taken bytes as a big-endian uint. Extracted to a
 * helper so the field-access workaround for Thales issue 8 stays
 * compact.
 */
/** @total */
function decodeCircIdFromSplit(sub: SplitResult): ParseCircIdResult {
  switch (sub.kind) {
    case 'short':
      return { kind: 'short' };
    case 'ok': {
      const subTaken = sub.taken;
      const subRest = sub.rest;
      return {
        kind: 'ok',
        circId: bigEndianUint(subTaken),
        rest: subRest,
      };
    }
  }
}

/**
 * Parse the circuit-ID prefix from `bs` for link protocol
 * `linkVersion`. Returns `.ok` with the decoded circId and the
 * remaining bytes, or `.short` if `bs` doesn't have enough bytes.
 */
/** @total */
function parseCircId(linkVersion: bigint, bs: ByteList): ParseCircIdResult {
  return decodeCircIdFromSplit(trySplit(circIdLengthForVersion(linkVersion), bs));
}
