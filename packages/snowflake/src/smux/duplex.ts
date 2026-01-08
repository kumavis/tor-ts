import { Duplex } from 'node:stream';
import type { SmuxStream } from './session.ts';

export type SmuxDuplexOptions = {
  readChunkSize?: number;
};

/**
 * Adapts a {@link SmuxStream} to a Node.js {@link Duplex}, suitable for `tls.connect({ socket })`.
 */
export class SmuxStreamDuplex extends Duplex {
  private readonly stream: SmuxStream;
  private readonly readChunkSize: number;
  private pumping = false;
  private ended = false;

  constructor(stream: SmuxStream, opts: SmuxDuplexOptions = {}) {
    super();
    this.stream = stream;
    this.readChunkSize = opts.readChunkSize ?? 16 * 1024;
  }

  override _read(_size: number): void {
    // Start (or resume) pump when consumer wants data.
    if (this.pumping || this.ended) return;
    this.pumping = true;
    void this.pump();
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    try {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, encoding) : chunk;
      const u8 = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      this.stream.write(u8);
      callback();
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  override _final(callback: (error?: Error | null) => void): void {
    try {
      this.stream.close();
      callback();
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    // Best-effort FIN.
    try {
      this.stream.close();
    } catch {
      // ignore
    }
    this.ended = true;
    callback(error);
  }

  private async pump(): Promise<void> {
    try {
      while (!this.ended) {
        let chunk: Uint8Array;
        try {
          chunk = await this.stream.readSome(this.readChunkSize);
        } catch {
          // Treat EOF-ish errors as end-of-stream.
          this.ended = true;
          this.push(null);
          return;
        }
        if (chunk.byteLength === 0) continue;
        const ok = this.push(Buffer.from(chunk));
        if (!ok) {
          // Backpressure: stop pumping until _read is called again.
          this.pumping = false;
          return;
        }
      }
    } finally {
      this.pumping = false;
    }
  }
}
