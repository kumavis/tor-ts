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
  /** Initial credit the peer gives us per stream; must match xtaci/smux default. */
  initialPeerWindow?: number;
  /** How often to emit NOP frames when there is no traffic (ms). 0 = disabled. */
  keepAliveIntervalMs?: number;
  /** Close the session if no frame is received within this window (ms). 0 = disabled. */
  keepAliveTimeoutMs?: number;
  /** Injection hook for tests that drive time. */
  now?: () => number;
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
};

// Match canonical defaults from xtaci/smux (mux.go:65-66).
const DEFAULT_KEEPALIVE_INTERVAL_MS = 10_000;
const DEFAULT_KEEPALIVE_TIMEOUT_MS = 30_000;
const DEFAULT_INITIAL_PEER_WINDOW = 262_144;
const DEFAULT_MAX_FRAME_SIZE = 32_768;
const DEFAULT_MAX_STREAM_BUFFER = 1_048_576;

export class SmuxSession extends EventEmitter {
  readonly ver: 2;
  readonly isClient: boolean;
  readonly maxFrameSize: number;
  readonly maxStreamBuffer: number;
  readonly initialPeerWindow: number;

  private readonly conn: SmuxUnderlying;
  private readonly now: () => number;
  private readonly setTimer: (cb: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private readonly keepAliveIntervalMs: number;
  private readonly keepAliveTimeoutMs: number;

  private nextSid: number;
  private readonly streams = new Map<number, SmuxStream>();
  private readonly accepts: SmuxStream[] = [];
  private acceptWaiters: Array<{
    resolve: (s: SmuxStream) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError: Error | undefined;

  private lastFrameReceivedAt: number;
  private keepAliveHandle: unknown;
  private keepAliveTimeoutHandle: unknown;

  constructor(conn: SmuxUnderlying, opts: SmuxSessionOptions) {
    super();
    this.conn = conn;
    this.ver = 2;
    this.isClient = opts.isClient;
    this.maxFrameSize = opts.maxFrameSize ?? DEFAULT_MAX_FRAME_SIZE;
    this.maxStreamBuffer = opts.maxStreamBuffer ?? DEFAULT_MAX_STREAM_BUFFER;
    this.initialPeerWindow = opts.initialPeerWindow ?? DEFAULT_INITIAL_PEER_WINDOW;
    this.nextSid = this.isClient ? 1 : 0;
    this.now = opts.now ?? (() => Date.now());
    this.setTimer =
      opts.setTimer ??
      ((cb, ms) => {
        const h = setInterval(cb, ms);
        // Don't keep the event loop alive just for keepalive pings.
        (h as unknown as { unref?: () => void }).unref?.();
        return h;
      });
    this.clearTimer =
      opts.clearTimer ?? ((h) => clearInterval(h as ReturnType<typeof setInterval>));
    this.keepAliveIntervalMs = opts.keepAliveIntervalMs ?? DEFAULT_KEEPALIVE_INTERVAL_MS;
    this.keepAliveTimeoutMs = opts.keepAliveTimeoutMs ?? DEFAULT_KEEPALIVE_TIMEOUT_MS;
    this.lastFrameReceivedAt = this.now();

    void this.recvLoop();

    if (this.keepAliveIntervalMs > 0) {
      this.keepAliveHandle = this.setTimer(
        () => this.sendKeepAlivePing(),
        this.keepAliveIntervalMs
      );
    }
    if (this.keepAliveTimeoutMs > 0) {
      this.keepAliveTimeoutHandle = this.setTimer(
        () => this.checkKeepAliveTimeout(),
        this.keepAliveTimeoutMs
      );
    }
  }

  async acceptStream(): Promise<SmuxStream> {
    if (this.closed) throw this.closeError ?? new Error('session closed');
    if (this.accepts.length > 0) return this.accepts.shift()!;
    return await new Promise<SmuxStream>((resolve, reject) => {
      this.acceptWaiters.push({ resolve, reject });
    });
  }

  async openStream(): Promise<SmuxStream> {
    if (this.closed) throw this.closeError ?? new Error('session closed');
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

  close(err?: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.closeError = err;
    if (this.keepAliveHandle !== undefined) {
      this.clearTimer(this.keepAliveHandle);
      this.keepAliveHandle = undefined;
    }
    if (this.keepAliveTimeoutHandle !== undefined) {
      this.clearTimer(this.keepAliveTimeoutHandle);
      this.keepAliveTimeoutHandle = undefined;
    }
    // Fail pending acceptors.
    const waiters = this.acceptWaiters;
    this.acceptWaiters = [];
    for (const w of waiters) w.reject(err ?? new Error('session closed'));
    // Propagate to streams.
    for (const stream of this.streams.values()) stream._onSessionClosed(err);
    this.streams.clear();
    this.emit('close');
  }

  isClosed(): boolean {
    return this.closed;
  }

  private sendKeepAlivePing(): void {
    if (this.closed) return;
    try {
      this.writeFrame(SMUX_CMD.NOP, 0, new Uint8Array(0));
    } catch (err) {
      this.close(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private checkKeepAliveTimeout(): void {
    if (this.closed) return;
    if (this.now() - this.lastFrameReceivedAt > this.keepAliveTimeoutMs) {
      const err = new Error(
        `smux: keepalive timeout (no frame for ${this.now() - this.lastFrameReceivedAt}ms)`
      );
      this.safeEmitError(err);
      this.close(err);
    }
  }

  private async recvLoop(): Promise<void> {
    try {
      for (;;) {
        if (this.closed) return;
        const hdr = await this.conn.readExactly(SMUX_HEADER_SIZE);
        const { ver, cmd, len, sid } = decodeSmuxHeader(hdr);
        if (ver !== this.ver) {
          throw new Error(`unsupported smux version: ${ver}`);
        }
        const payload = len > 0 ? await this.conn.readExactly(len) : new Uint8Array(0);
        this.lastFrameReceivedAt = this.now();
        this.onFrame(cmd, sid, payload);
      }
    } catch (err) {
      if (this.closed) return;
      const e = err instanceof Error ? err : new Error(String(err));
      // EOF means the carrier closed gracefully (e.g. our own kcp.close()
      // during shutdown). That's not an error condition — just a close —
      // and emitting 'error' here when nothing listens crashes the process
      // because EventEmitter mandates a listener for 'error' events.
      const isOrderlyClose = e.message === 'EOF';
      if (!isOrderlyClose) this.safeEmitError(e);
      this.close(isOrderlyClose ? undefined : e);
    }
  }

  /** emit('error') with no listener is fatal to the Node process — guard it. */
  private safeEmitError(err: Error): void {
    if (this.listenerCount('error') > 0) {
      this.emit('error', err);
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

    if (cmd === SMUX_CMD.NOP) {
      // Only a liveness signal; lastFrameReceivedAt is already updated.
      return;
    }

    const stream = this.streams.get(sid);
    if (!stream) return;

    switch (cmd) {
      case SMUX_CMD.PSH:
        stream._onData(payload);
        return;
      case SMUX_CMD.FIN:
        stream._onFin();
        return;
      case SMUX_CMD.UPD: {
        const { consumed, window } = decodeUpdPayload(payload);
        stream._onUpd(consumed, window);
        return;
      }
      default:
        return;
    }
  }

  private enqueueAccept(stream: SmuxStream): void {
    const waiter = this.acceptWaiters.shift();
    if (waiter) {
      waiter.resolve(stream);
      return;
    }
    this.accepts.push(stream);
  }

  _removeStream(sid: number): void {
    this.streams.delete(sid);
  }
}

type WriteWaiter = {
  resolve: () => void;
  reject: (err: Error) => void;
};

export class SmuxStream {
  private readonly sess: SmuxSession;
  readonly sid: number;

  private readonly rx = new ByteQueue();
  private fin = false;
  private closedErr: Error | undefined;

  // v2 flow control
  private numRead = 0;
  private numWritten = 0;
  private peerConsumed = 0;
  private peerWindow: number;
  private incrSinceLastUpd = 0;
  private sentInitialUpd = false;
  private readonly writeWaiters: WriteWaiter[] = [];

  constructor(sess: SmuxSession, sid: number) {
    this.sess = sess;
    this.sid = sid >>> 0;
    this.peerWindow = sess.initialPeerWindow;
  }

  _onData(data: Uint8Array): void {
    this.rx.push(data.slice());
  }

  _onFin(): void {
    this.fin = true;
    // Mark the stream locally closed too — once the peer has sent FIN it has
    // forgotten our sid, so any further PSH we send is silently dropped.
    // Without setting closedErr, write()'s only guard would let new writes
    // through (silent data loss). Use ??= to preserve any prior close error.
    this.closedErr ??= new Error('EOF');
    this.rx.close();
    // No more writes will be accepted on peer's end; unblock any pending writers.
    this.rejectWriteWaiters(this.closedErr);
    this.sess._removeStream(this.sid);
  }

  _onUpd(consumed: number, window: number): void {
    this.peerConsumed = consumed >>> 0;
    this.peerWindow = window >>> 0;
    this.wakeWriteWaiters();
  }

  _onSessionClosed(err?: Error): void {
    this.closedErr = err ?? new Error('session closed');
    this.fin = true;
    this.rx.close();
    this.rejectWriteWaiters(this.closedErr);
  }

  async readExactly(n: number): Promise<Uint8Array> {
    if (this.closedErr) throw this.closedErr;
    try {
      await this.rx.waitForAtLeast(n);
    } catch (err) {
      if (this.closedErr) throw this.closedErr;
      throw err;
    }
    const out = this.rx.readExactly(n);
    this.accountRead(out.byteLength);
    return out;
  }

  async readSome(n: number): Promise<Uint8Array> {
    if (this.closedErr) throw this.closedErr;
    try {
      await this.rx.waitForAtLeast(1);
    } catch (err) {
      if (this.closedErr) throw this.closedErr;
      throw err;
    }
    const take = Math.min(n, this.rx.length);
    const out = this.rx.readExactly(take);
    this.accountRead(out.byteLength);
    if (out.byteLength === 0 && this.fin) throw new Error('EOF');
    return out;
  }

  /**
   * Write with v2 credit-based backpressure. Resolves after all bytes have been
   * handed to the session, which may take multiple wakeups as peer credit arrives.
   */
  async write(data: Uint8Array): Promise<void> {
    if (this.closedErr) throw this.closedErr;
    if (data.byteLength === 0) return;

    let off = 0;
    while (off < data.byteLength) {
      // Compute available peer window in 32-bit modular arithmetic (matches smux v2).
      const inflight = (this.numWritten - this.peerConsumed) >>> 0;
      if (inflight > 0x7fffffff) {
        // Defensive: peer claims to have consumed more than we sent.
        throw new Error('smux: peer consumed more than sent');
      }
      // No credit when we've already filled the peer's window. We must NOT
      // compute `(peerWindow - inflight) >>> 0` here: that underflows to a
      // huge unsigned value when inflight > peerWindow, which would defeat
      // backpressure precisely when it should block.
      if (inflight >= this.peerWindow) {
        await this.waitForWriteWindow();
        continue;
      }
      const win = this.peerWindow - inflight;
      const remaining = data.byteLength - off;
      const take = Math.min(this.sess.maxFrameSize, remaining, win);
      const chunk = data.subarray(off, off + take);
      this.sess.writeFrame(SMUX_CMD.PSH, this.sid, chunk);
      this.numWritten = (this.numWritten + take) >>> 0;
      off += take;
    }
  }

  close(): void {
    if (this.closedErr) return;
    try {
      this.sess.writeFrame(SMUX_CMD.FIN, this.sid, new Uint8Array(0));
    } catch {
      // ignore — session may already be closed
    }
    // Mark the stream locally closed so subsequent write()s throw fast and
    // any pending write-window waiters wake up with an error rather than
    // hanging. Once removed from the session map (below), the stream cannot
    // receive any more inbound frames, so close rx too — pending readers
    // would otherwise wait forever for bytes that will never arrive.
    this.closedErr = new Error('stream closed');
    this.rejectWriteWaiters(this.closedErr);
    this.rx.close();
    this.sess._removeStream(this.sid);
  }

  private accountRead(n: number): void {
    if (n === 0) return;
    this.numRead = (this.numRead + n) >>> 0;
    this.incrSinceLastUpd += n;
    // Canonical smux v2: send UPD on initial read OR when the accumulated
    // unacked-read bytes reach half the stream buffer. Sending on every
    // read floods the carrier and is a major amplifier of KCP packet count.
    const threshold = Math.max(1, Math.floor(this.sess.maxStreamBuffer / 2));
    if (!this.sentInitialUpd || this.incrSinceLastUpd >= threshold) {
      this.sendUpd();
      this.sentInitialUpd = true;
      this.incrSinceLastUpd = 0;
    }
  }

  private sendUpd(): void {
    try {
      const payload = encodeUpdPayload(this.numRead >>> 0, this.sess.maxStreamBuffer >>> 0);
      this.sess.writeFrame(SMUX_CMD.UPD, this.sid, payload);
    } catch {
      // Session likely closed; nothing to do.
    }
  }

  private waitForWriteWindow(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.writeWaiters.push({ resolve, reject });
    });
  }

  private wakeWriteWaiters(): void {
    const waiters = this.writeWaiters.splice(0);
    for (const w of waiters) w.resolve();
  }

  private rejectWriteWaiters(err: Error): void {
    const waiters = this.writeWaiters.splice(0);
    for (const w of waiters) w.reject(err);
  }
}
