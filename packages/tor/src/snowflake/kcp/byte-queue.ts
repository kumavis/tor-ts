export class ByteQueue {
  private chunks: Uint8Array[] = [];
  private size = 0;
  private waiters: Array<() => void> = [];

  push(chunk: Uint8Array): void {
    if (chunk.byteLength === 0) return;
    this.chunks.push(chunk);
    this.size += chunk.byteLength;
    const waiters = this.waiters;
    this.waiters = [];
    for (const w of waiters) w();
  }

  get length(): number {
    return this.size;
  }

  async waitForAtLeast(n: number): Promise<void> {
    if (this.size >= n) return;
    await new Promise<void>((resolve) => {
      this.waiters.push(resolve);
    });
    return this.waitForAtLeast(n);
  }

  readExactly(n: number): Uint8Array {
    if (n === 0) return new Uint8Array(0);
    if (this.size < n) throw new Error(`ByteQueue underflow: need ${n}, have ${this.size}`);
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const head = this.chunks[0]!;
      const take = Math.min(head.byteLength, n - off);
      out.set(head.subarray(0, take), off);
      off += take;
      if (take === head.byteLength) {
        this.chunks.shift();
      } else {
        this.chunks[0] = head.subarray(take);
      }
    }
    this.size -= n;
    return out;
  }
}

