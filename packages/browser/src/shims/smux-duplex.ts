/**
 * Browser-compatible SmuxStreamDuplex replacement.
 * Uses the polyfilled stream module from vite-plugin-node-polyfills.
 */

import { Duplex } from 'stream';
import type { SmuxStream } from 'snowflake/smux';

/**
 * Wraps a SmuxStream as a Node.js-style Duplex stream.
 * This works in browsers via the stream polyfill.
 */
export class SmuxStreamDuplex extends Duplex {
  private smux: SmuxStream;
  private reading = false;

  constructor(smux: SmuxStream) {
    super();
    this.smux = smux;
    void this.startReading();
  }

  private async startReading(): Promise<void> {
    if (this.reading) return;
    this.reading = true;
    try {
      while (this.reading) {
        const chunk = await this.smux.readSome(16384);
        if (chunk.byteLength === 0) {
          this.push(null);
          break;
        }
        const ok = this.push(Buffer.from(chunk));
        if (!ok) {
          // Backpressure - wait for drain
          await new Promise<void>((resolve) => this.once('drain', resolve));
        }
      }
    } catch (err) {
      if ((err as Error).message === 'EOF') {
        this.push(null);
      } else {
        this.destroy(err as Error);
      }
    }
  }

  override _read(_size: number): void {
    // Reading is driven by startReading loop
  }

  override _write(
    chunk: Buffer | Uint8Array,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    const data = chunk instanceof Uint8Array ? chunk : Uint8Array.from(chunk);
    this.smux
      .write(data)
      .then(() => callback())
      .catch((err) => callback(err as Error));
  }

  override _final(callback: (error?: Error | null) => void): void {
    try {
      this.smux.close();
      callback();
    } catch (err) {
      callback(err as Error);
    }
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.reading = false;
    callback(error);
  }
}
