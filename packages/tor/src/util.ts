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

/**
 * One-shot Promise-shaped latch that holds its settled state instead of
 * keeping a Promise around.
 *
 * Why this exists: with `Promise.withResolvers()` (or any deferred), calling
 * `reject()` before any consumer has attached to `.promise` produces an
 * unhandled rejection that crashes Node. The fix used to be a no-op
 * `.catch()` at construction time, which silenced *all* errors from that
 * kit — too coarse.
 *
 * `PromiseLatch` instead records the resolution/rejection synchronously and
 * only materializes a Promise when a caller actually calls `wait()`. If
 * nobody ever waits, `reject()` is a tree-falls-in-the-forest no-op — no
 * Promise object exists, so there's nothing for the runtime to flag as
 * unhandled. Late awaiters (after settlement) get a fresh Promise that
 * resolves/rejects immediately from the cached state.
 *
 * Behaviour matches `Promise.withResolvers()` for the cases that matter:
 *  - `wait()` before settlement → Promise resolves/rejects when settlement happens
 *  - Multiple `wait()` callers each get an independent Promise, all settling together
 *  - Late `wait()` after settlement → Promise that's already in the right state
 *
 * Differs from `Promise.withResolvers()` in one place: a second `resolve()`
 * or `reject()` is a programmer error and throws synchronously rather than
 * being silently ignored. Latch settlement is one-shot; a re-settle attempt
 * usually means a bug in the caller (e.g. handling the same response twice
 * or racing two destroy paths against the success path). Use `isPending()`
 * to gate the call when racing is intentional.
 */
export class PromiseLatch<T = void> {
  private state: 'pending' | 'resolved' | 'rejected' = 'pending';
  private resolvedValue: T | undefined;
  private rejectionReason: Error | undefined;
  private resolveCallbacks: Array<(value: T) => void> = [];
  private rejectCallbacks: Array<(err: Error) => void> = [];

  /**
   * Settle with a resolved value. Throws if the latch has already been
   * resolved or rejected. When `T` is `void` the argument is omitted.
   */
  resolve(...args: T extends void ? [] : [value: T]): void {
    if (this.state !== 'pending') {
      throw new Error(`PromiseLatch.resolve() called on already-${this.state} latch`);
    }
    const value = (args.length === 0 ? (undefined as unknown as T) : args[0]) as T;
    this.state = 'resolved';
    this.resolvedValue = value;
    const cbs = this.resolveCallbacks;
    this.resolveCallbacks = [];
    this.rejectCallbacks = [];
    for (const cb of cbs) cb(value);
  }

  /**
   * Settle with a rejection. Throws if the latch has already been resolved
   * or rejected.
   */
  reject(err: Error): void {
    if (this.state !== 'pending') {
      throw new Error(`PromiseLatch.reject() called on already-${this.state} latch`);
    }
    this.state = 'rejected';
    this.rejectionReason = err;
    const cbs = this.rejectCallbacks;
    this.resolveCallbacks = [];
    this.rejectCallbacks = [];
    for (const cb of cbs) cb(err);
  }

  wait(): Promise<T> {
    if (this.state === 'resolved') return Promise.resolve(this.resolvedValue as T);
    if (this.state === 'rejected') return Promise.reject(this.rejectionReason);
    return new Promise<T>((resolve, reject) => {
      this.resolveCallbacks.push(resolve);
      this.rejectCallbacks.push(reject);
    });
  }

  isPending(): boolean {
    return this.state === 'pending';
  }

  isSettled(): boolean {
    return this.state !== 'pending';
  }
}
