export { sha256, sha1 } from 'tor-crypto';
import { randomBytes } from 'tor-crypto';

/**
 * Fisher-Yates shuffle using cryptographically secure random bytes.
 * Works in both Node.js and browser environments via tor-crypto.
 *
 * @param arr - Array to shuffle in place
 * @returns The same array, shuffled
 */
export function shuffleInPlace<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const randBytes = randomBytes(4);
    // Use 3 bytes for randomness (up to ~16M), mod by (i+1)
    const rand = (randBytes[0]! | (randBytes[1]! << 8) | (randBytes[2]! << 16)) >>> 0;
    const j = rand % (i + 1);
    const tmp = arr[i]!;
    arr[i] = arr[j]!;
    arr[j] = tmp;
  }
  return arr;
}

export class BytesReader {
  data: Buffer;
  offset: number;
  constructor(data: Buffer) {
    this.data = data;
    this.offset = 0;
  }
  readUIntBE(length: number) {
    if (this.offset + length > this.data.length)
      throw new Error(
        `Bytes reader: Attempted to read ${length} bytes but only ${this.data.length - this.offset} bytes remain`
      );
    const value = this.data.readUIntBE(this.offset, length);
    this.offset += length;
    return value;
  }
  readBytes(length: number, { allowShorter = false }: { allowShorter?: boolean } = {}) {
    if (!allowShorter && this.offset + length > this.data.length)
      throw new Error(
        `Bytes reader: Attempted to read ${length} bytes but only ${this.data.length - this.offset} bytes remain`
      );
    const bytes = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }
  readRemainder() {
    const bytes = this.data.slice(this.offset);
    this.offset = this.data.length;
    return bytes;
  }
  isExhausted() {
    return this.offset >= this.data.length;
  }
  get length() {
    return this.data.length;
  }
}

export function bufferFromUint(length: number, value: number) {
  if (typeof value !== 'number') throw new Error('value must be a number');
  const data = Buffer.alloc(length);
  data.writeUintBE(value, 0, length);
  return data;
}

export class Mutex {
  private current: Promise<void> = Promise.resolve();

  lock(): Promise<() => void> {
    let resolveLock!: () => void;
    const p = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    // Caller gets a promise that resolves when the current outstanding lock resolves.
    const unlockP = this.current.then(() => resolveLock);

    // Don't allow the next request until the new promise is done.
    this.current = p;

    return unlockP;
  }
}
