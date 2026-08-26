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

// ----------------------------------------------------------------------------
// Command-byte parsing.
//
// After the circuit ID, every cell carries a single command byte. This
// function returns the raw `bigint` code; the caller (or the next
// slice) interprets it as a `MessageCellType` via the lookup table in
// `messageCellType.ts`. Keeping the type interpretation out of this
// module avoids redeclaring the 18-variant DU here on top of the
// already-redeclared bytes primitives (Thales 0.5 has no `import` —
// issue 5 in docs/thales-issues.md).
// ----------------------------------------------------------------------------

type ParseCommandResult = { kind: 'ok'; commandCode: bigint; rest: ByteList } | { kind: 'short' };

/**
 * Read one byte off the head of `bs` as a command code. Returns
 * `.short` only on empty input.
 */
/** @total */
function parseCommand(bs: ByteList): ParseCommandResult {
  switch (bs.kind) {
    case 'nil':
      return { kind: 'short' };
    case 'cons': {
      // Bind to consts before constructing the result (issue-8 workaround).
      const head = bs.head;
      const tail = bs.tail;
      return { kind: 'ok', commandCode: head, rest: tail };
    }
  }
}

// ----------------------------------------------------------------------------
// Length-prefix parsing.
//
// Variable-length cells (per `isVariableLengthCell` in messageCellType.ts)
// announce their payload size with a 2-byte big-endian length immediately
// after the command byte (tor-spec.txt §3, "Variable-length cell"
// layout).
// ----------------------------------------------------------------------------

type ParseLengthResult = { kind: 'ok'; length: bigint; rest: ByteList } | { kind: 'short' };

/** @total */
function decodeLengthFromSplit(sub: SplitResult): ParseLengthResult {
  switch (sub.kind) {
    case 'short':
      return { kind: 'short' };
    case 'ok': {
      const subTaken = sub.taken;
      const subRest = sub.rest;
      return {
        kind: 'ok',
        length: bigEndianUint(subTaken),
        rest: subRest,
      };
    }
  }
}

/**
 * Read a 2-byte big-endian length prefix off the head of `bs`. The
 * decoded length is in `[0, 65536)`.
 */
/** @total */
function parseLengthPrefix(bs: ByteList): ParseLengthResult {
  return decodeLengthFromSplit(trySplit(2n, bs));
}

// ----------------------------------------------------------------------------
// Payload parsing.
//
// Once the cell type is known, the payload is either a fixed
// `CELL_PAYLOAD_LEN`-byte body (the standard 509 bytes for fixed-length
// cells) or `length`-byte body (for variable-length cells, where
// `length` came from `parseLengthPrefix`).
// ----------------------------------------------------------------------------

/** Standard fixed-length cell payload size (tor-spec.txt §3, PAYLOAD_LEN). */
const CELL_PAYLOAD_LEN: bigint = 509n;

type ParsePayloadResult = { kind: 'ok'; payload: ByteList; rest: ByteList } | { kind: 'short' };

/** @total */
function decodePayloadFromSplit(sub: SplitResult): ParsePayloadResult {
  switch (sub.kind) {
    case 'short':
      return { kind: 'short' };
    case 'ok': {
      const subTaken = sub.taken;
      const subRest = sub.rest;
      return {
        kind: 'ok',
        payload: subTaken,
        rest: subRest,
      };
    }
  }
}

/**
 * Take exactly `n` bytes off the head of `bs` as a payload, returning
 * the payload and the remainder. Wraps `trySplit` with a payload-shaped
 * result so callers can pattern-match on the parser-specific DU
 * without leaking the lower-level `SplitResult`.
 */
/** @total */
function parsePayload(n: bigint, bs: ByteList): ParsePayloadResult {
  return decodePayloadFromSplit(trySplit(n, bs));
}

/**
 * Convenience: read the standard 509-byte fixed-cell payload.
 */
/** @total */
function parseFixedPayload(bs: ByteList): ParsePayloadResult {
  return parsePayload(CELL_PAYLOAD_LEN, bs);
}
