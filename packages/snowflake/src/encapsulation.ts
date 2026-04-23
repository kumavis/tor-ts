// Snowflake "encapsulation" framing, compatible with
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/encapsulation
//
// It encodes variable-length "data" and "padding" chunks into a byte stream.
// We only need "data" for a Snowflake client, but the decoder must skip padding.

export class EncapsulationTooLongError extends Error {
  override name = 'EncapsulationTooLongError';
  constructor(message = 'length prefix is too long') {
    super(message);
  }
}

export class EncapsulationUnexpectedEofError extends Error {
  override name = 'EncapsulationUnexpectedEofError';
  constructor(message = 'unexpected EOF while decoding encapsulation') {
    super(message);
  }
}

/**
 * Encode a data chunk (d=1) with a 1–3 byte length prefix.
 * Max encodable length is 0xfffff (1048575).
 */
export function encodeEncapsulatedData(data: Uint8Array): Uint8Array {
  const n = data.byteLength;
  const prefix = dataPrefixForLength(n);
  const out = new Uint8Array(prefix.byteLength + n);
  out.set(prefix, 0);
  out.set(data, prefix.byteLength);
  return out;
}

/**
 * Stateful decoder for encapsulation chunks.
 *
 * Feed it bytes via {@link push}, and drain available data chunks via {@link popData}.
 * Padding chunks are automatically skipped.
 */
export class EncapsulationDecoder {
  // Internal buffer (simple grow-only with compaction).
  private buf = new Uint8Array(0);
  private off = 0;

  push(chunk: Uint8Array): void {
    if (chunk.byteLength === 0) return;
    // Compact if we've consumed a lot.
    if (this.off > 0 && this.off === this.buf.byteLength) {
      this.buf = new Uint8Array(0);
      this.off = 0;
    } else if (this.off > 0 && this.off > 1024 && this.off > this.buf.byteLength / 2) {
      this.buf = this.buf.slice(this.off);
      this.off = 0;
    }

    if (this.buf.byteLength === 0) {
      this.buf = chunk.slice();
      this.off = 0;
      return;
    }

    const remaining = this.buf.byteLength - this.off;
    const next = new Uint8Array(remaining + chunk.byteLength);
    next.set(this.buf.subarray(this.off), 0);
    next.set(chunk, remaining);
    this.buf = next;
    this.off = 0;
  }

  /**
   * Returns the next fully-decoded data chunk, or undefined if not enough bytes are buffered yet.
   *
   * Throws on malformed prefixes (too long) or if called after end-of-stream when a partial frame exists.
   */
  popData(): Uint8Array | undefined {
    // We may need to skip one or more padding chunks.
    // Loop until we either return a data chunk or need more bytes.
    while (true) {
      const hdr = this.tryReadLengthPrefix();
      if (!hdr) return undefined;
      const { isData, length, headerBytes } = hdr;

      const avail = this.buf.byteLength - this.off;
      if (avail < headerBytes + length) return undefined;

      // Consume header.
      this.off += headerBytes;

      if (!isData) {
        // Skip padding bytes.
        this.off += length;
        continue;
      }

      const payload = this.buf.subarray(this.off, this.off + length);
      this.off += length;
      // Copy to detach from internal buffer.
      return payload.slice();
    }
  }

  /**
   * Signal end-of-stream. If there is an incomplete chunk buffered, throws.
   */
  finish(): void {
    // If any remaining bytes exist, they must be a full prefix+payload; otherwise it's an unexpected EOF.
    if (this.buf.byteLength === this.off) return;
    const hdr = this.tryReadLengthPrefix();
    if (!hdr) throw new EncapsulationUnexpectedEofError();
    const avail = this.buf.byteLength - this.off;
    if (avail < hdr.headerBytes + hdr.length) throw new EncapsulationUnexpectedEofError();
    // If it is a complete padding chunk, that’s okay (but unusual); consume and ensure nothing remains.
    this.off += hdr.headerBytes + hdr.length;
    if (this.buf.byteLength !== this.off) {
      // Could be multiple complete chunks; consume them all.
      while (this.buf.byteLength !== this.off) {
        const h = this.tryReadLengthPrefix();
        if (!h) throw new EncapsulationUnexpectedEofError();
        const a = this.buf.byteLength - this.off;
        if (a < h.headerBytes + h.length) throw new EncapsulationUnexpectedEofError();
        this.off += h.headerBytes + h.length;
      }
    }
  }

  private tryReadLengthPrefix():
    | { isData: boolean; length: number; headerBytes: number }
    | undefined {
    const avail = this.buf.byteLength - this.off;
    if (avail < 1) return undefined;

    const b0 = this.buf[this.off]!;
    const isData = (b0 & 0x80) !== 0;
    let more = (b0 & 0x40) !== 0;
    let n = b0 & 0x3f;
    let headerBytes = 1;

    for (let i = 0; more; i++) {
      if (i >= 2) throw new EncapsulationTooLongError();
      if (avail < headerBytes + 1) return undefined;
      const bi = this.buf[this.off + headerBytes]!;
      headerBytes += 1;
      more = (bi & 0x80) !== 0;
      n = (n << 7) | (bi & 0x7f);
    }

    return { isData, length: n, headerBytes };
  }
}

/**
 * Encode one or more padding chunks whose *total* encoded size (prefix + body)
 * is `totalBytes`. Mirrors snowflake common/encapsulation.WritePadding, which
 * picks a prefix size that lets the body exactly fill the remaining budget.
 *
 * The padding payload has no semantic meaning; bytes come from `randomBytes`
 * so repeated preambles don't share a fingerprint.
 */
export function encodeEncapsulatedPadding(
  totalBytes: number,
  randomBytes: (n: number) => Uint8Array = (n) => new Uint8Array(n)
): Uint8Array {
  if (totalBytes < 0) throw new Error('negative length');
  if (totalBytes === 0) return new Uint8Array(0);

  const parts: Uint8Array[] = [];
  let remaining = totalBytes;
  const CHUNK_MAX = 1024;

  while (remaining > 0) {
    let p = Math.min(CHUNK_MAX, remaining);
    remaining -= p;

    let prefix: Uint8Array;
    if ((((p - 1) >> 0) & 0x3f) === ((p - 1) >> 0)) {
      p = p - 1;
      prefix = Uint8Array.of((p >> 0) & 0x3f);
    } else if ((((p - 2) >> 7) & 0x3f) === ((p - 2) >> 7)) {
      p = p - 2;
      prefix = Uint8Array.of(0x40 | ((p >> 7) & 0x3f), (p >> 0) & 0x7f);
    } else {
      p = p - 3;
      prefix = Uint8Array.of(
        0x40 | ((p >> 14) & 0x3f),
        0x80 | ((p >> 7) & 0x3f),
        (p >> 0) & 0x7f
      );
    }

    parts.push(prefix, randomBytes(p));
  }

  const total = parts.reduce((a, b) => a + b.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.byteLength;
  }
  return out;
}

function dataPrefixForLength(n: number): Uint8Array {
  // Mirrors snowflake/common/encapsulation/dataPrefixForLength.
  // 1 byte: 0b10xxxxxx where xxxxxx = n
  if (((n >> 0) & 0x3f) === n >> 0) {
    return Uint8Array.of(0x80 | ((n >> 0) & 0x3f));
  }
  // 2 bytes: 0b11xxxxxx 0yyyyyyy where xxxxxx yyyyyyy = n
  if (((n >> 7) & 0x3f) === n >> 7) {
    return Uint8Array.of(0xc0 | ((n >> 7) & 0x3f), (n >> 0) & 0x7f);
  }
  // 3 bytes: 0b11xxxxxx 1yyyyyyy 0zzzzzzz where concatenation = n
  if (((n >> 14) & 0x3f) === n >> 14) {
    return Uint8Array.of(0xc0 | ((n >> 14) & 0x3f), 0x80 | ((n >> 7) & 0x7f), (n >> 0) & 0x7f);
  }
  throw new EncapsulationTooLongError();
}
