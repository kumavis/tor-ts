import * as crypto from "node:crypto";

export class BytesReader {
  data: Buffer;
  offset: number;
  constructor (data: Buffer) {
    this.data = data;
    this.offset = 0;
  }
  readUIntBE (length: number) {
    if (this.offset + length > this.data.length) throw new Error('out of bounds')
    const value = this.data.readUIntBE(this.offset, length);
    this.offset += length;
    return value
  }
  readBytes (length: number, { allowShorter = false}: { allowShorter?: boolean } = {}) {
    if (!allowShorter && (this.offset + length > this.data.length)) throw new Error('out of bounds')
    const bytes = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes
  }
  readRemainder () {
    const bytes = this.data.slice(this.offset);
    this.offset = this.data.length;
    return bytes;
  }
  isExhausted () {
    return this.offset >= this.data.length
  }
  get length () {
    return this.data.length
  }
}

export function bufferFromUint (length: number, value: number) {
  if (typeof value !== 'number') throw new Error('value must be a number')
  const data = Buffer.alloc(length);
  data.writeUintBE(value, 0, length);
  return data;
}

export const sha256 = (...data: Buffer[]): Buffer => {
	const hash = crypto.createHash('sha256')
  for (const d of data) {
    hash.update(d)
  }
  return hash.digest()
}

export const sha1 = (...data: Buffer[]): Buffer => {
  const hash = crypto.createHash('sha1')
  for (const d of data) {
    hash.update(d)
  }
  return hash.digest()
}

export const deferred = <T> (): { promise: Promise<T>, resolve: (value: T) => void, reject: (reason?: any) => void } => {
  let resolve: (value: T) => void;
  let reject: (reason?: any) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve: resolve!, reject: reject! }
}