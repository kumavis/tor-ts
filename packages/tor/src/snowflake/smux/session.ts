import { EventEmitter } from 'node:events';
import { ByteQueue } from '../kcp/byte-queue.ts';
import {
  decodeSmuxHeader,
  decodeUpdPayload,
  encodeSmuxFrame,
  encodeUpdPayload,
  SMUX_CMD,
  SMUX_HEADER_SIZE,
} from './protocol.ts';
import type { SmuxCmd } from './protocol.ts';

export type SmuxUnderlying = {
  readExactly(n: number): Promise<Uint8Array>;
  write(data: Uint8Array): void;
};

export type SmuxSessionOptions = {
  ver?: 2;
  isClient: boolean;
  maxFrameSize?: number;
  maxStreamBuffer?: number;
};

export class SmuxSession extends EventEmitter {
  readonly ver: 2;
  readonly isClient: boolean;
  readonly maxFrameSize: number;
  readonly maxStreamBuffer: number;

  private readonly conn: SmuxUnderlying;
  private nextSid: number;
  private readonly streams = new Map<number, SmuxStream>();
  private readonly accepts: SmuxStream[] = [];
  private acceptWaiters: Array<(s: SmuxStream) => void> = [];
  private closed = false;

  constructor(conn: SmuxUnderlying, opts: SmuxSessionOptions) {
    super();
    this.conn = conn;
    this.ver = 2;
    this.isClient = opts.isClient;
    this.maxFrameSize = opts.maxFrameSize ?? 32768;
    this.maxStreamBuffer = opts.maxStreamBuffer ?? 1024 * 1024;
    this.nextSid = this.isClient ? 1 : 0;
    void this.recvLoop();
  }

  async acceptStream(): Promise<SmuxStream> {
    if (this.accepts.length > 0) return this.accepts.shift()!;
    return await new Promise<SmuxStream>((resolve) => {
      this.acceptWaiters.push(resolve);
    });
  }

  async openStream(): Promise<SmuxStream> {
    if (this.closed) throw new Error('session closed');
    this.nextSid += 2;
    const sid = this.nextSid >>> 0;
    const stream = new SmuxStream(this, sid);
    this.streams.set(sid, stream);
    this.writeFrame(SMUX_CMD.SYN, sid, new Uint8Array(0));
    return stream;
  }

  writeFrame(cmd: SmuxCmd, sid: number, payload: Uint8Array): void {
    this.conn.write(encodeSmuxFrame({ ver: this.ver, cmd, sid, data: payload }));
  }

  close(): void {
    this.closed = true;
    this.emit('close');
  }

  private async recvLoop(): Promise<void> {
    try {
      for (;;) {
        const hdr = await this.conn.readExactly(SMUX_HEADER_SIZE);
        const { ver, cmd, len, sid } = decodeSmuxHeader(hdr);
        if (ver !== this.ver) {
          throw new Error(`unsupported smux version: ${ver}`);
        }
        const payload = len > 0 ? await this.conn.readExactly(len) : new Uint8Array(0);
        this.onFrame(cmd, sid, payload);
      }
    } catch (err) {
      this.emit('error', err);
      this.close();
    }
  }

  private onFrame(cmd: SmuxCmd, sid: number, payload: Uint8Array): void {
    if (cmd === SMUX_CMD.SYN) {
      let stream = this.streams.get(sid);
      if (!stream) {
        stream = new SmuxStream(this, sid);
        this.streams.set(sid, stream);
      }
      this.enqueueAccept(stream);
      return;
    }

    const stream = this.streams.get(sid);
    if (!stream) {
      // Unknown stream; ignore.
      return;
    }

    switch (cmd) {
      case SMUX_CMD.PSH:
        stream.onData(payload);
        return;
      case SMUX_CMD.FIN:
        stream.onFin();
        return;
      case SMUX_CMD.NOP:
        return;
      case SMUX_CMD.UPD: {
        const { consumed, window } = decodeUpdPayload(payload);
        stream.onUpd(consumed, window);
        return;
      }
      default:
        return;
    }
  }

  private enqueueAccept(stream: SmuxStream): void {
    const waiter = this.acceptWaiters.shift();
    if (waiter) {
      waiter(stream);
      return;
    }
    this.accepts.push(stream);
  }
}

export class SmuxStream {
  private readonly sess: SmuxSession;
  readonly sid: number;

  private readonly rx = new ByteQueue();
  private fin = false;

  // v2 flow control
  private numRead = 0;
  private numWritten = 0;
  private peerConsumed = 0;
  private peerWindow = 262144; // initialPeerWindow in xtaci/smux

  constructor(sess: SmuxSession, sid: number) {
    this.sess = sess;
    this.sid = sid >>> 0;
  }

  onData(data: Uint8Array): void {
    this.rx.push(data.slice());
  }

  onFin(): void {
    this.fin = true;
    this.rx.close();
  }

  onUpd(consumed: number, window: number): void {
    this.peerConsumed = consumed >>> 0;
    this.peerWindow = window >>> 0;
  }

  async readExactly(n: number): Promise<Uint8Array> {
    await this.rx.waitForAtLeast(n);
    const out = this.rx.readExactly(n);
    if (out.byteLength > 0) {
      this.numRead += out.byteLength;
      this.sendUpd();
      return out;
    }
    if (this.fin) throw new Error('EOF');
    return out;
  }

  async readSome(n: number): Promise<Uint8Array> {
    await this.rx.waitForAtLeast(1);
    const take = Math.min(n, this.rx.length);
    const out = this.rx.readExactly(take);
    if (out.byteLength > 0) {
      this.numRead += out.byteLength;
      this.sendUpd();
      return out;
    }
    if (this.fin) throw new Error('EOF');
    return out;
  }

  write(data: Uint8Array): void {
    if (data.byteLength === 0) return;
    let off = 0;
    while (off < data.byteLength) {
      const take = Math.min(this.sess.maxFrameSize, data.byteLength - off);
      const chunk = data.subarray(off, off + take);
      off += take;
      // Minimal v2 flow control:
      // We currently *do not* block on peerWindow; we only track it.
      // This is sufficient for small handshakes and can be extended to async backpressure later.
      this.sess.writeFrame(SMUX_CMD.PSH, this.sid, chunk);
      this.numWritten += chunk.byteLength;
    }
  }

  close(): void {
    this.sess.writeFrame(SMUX_CMD.FIN, this.sid, new Uint8Array(0));
  }

  private sendUpd(): void {
    const payload = encodeUpdPayload(this.numRead >>> 0, this.sess.maxStreamBuffer >>> 0);
    this.sess.writeFrame(SMUX_CMD.UPD, this.sid, payload);
  }
}

