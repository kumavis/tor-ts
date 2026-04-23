import { ByteQueue } from './byte-queue.ts';
import { decodeKcpSegmentsFromPacket, encodeKcpSegment, KCP_CMD } from './segment.ts';
import type { KcpSegment } from './segment.ts';

export type KcpPacketSink = (pkt: Uint8Array) => void;

export type KcpSessionOptions = {
  conv: number;
  now?: () => number; // milliseconds
  mss?: number;
  wnd?: number;
  rtoInitial?: number;
  rtoMax?: number;
  deadLink?: number;
  flushIntervalMs?: number;
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
};

// Defaults aligned with xtaci/kcp-go.
const DEFAULT_RTO_INITIAL = 200; // ms
const DEFAULT_RTO_MAX = 60_000; // ms
const DEFAULT_DEAD_LINK = 30;
const DEFAULT_FLUSH_INTERVAL = 20; // ms

type Unacked = {
  seg: KcpSegment;
  resendts: number;
  rto: number;
  xmit: number;
  firstSentAt: number;
};

/**
 * Reliable KCP session compatible with xtaci/kcp-go stream-mode wire format.
 *
 * This implementation:
 *  - coalesces writes into MSS-sized PUSH segments (stream mode)
 *  - tracks send buffer and retransmits on RTO expiry
 *  - advances sender state from incoming ACKs AND from `una` piggybacked on any segment
 *  - runs a periodic `update()` flush (optional; tests may drive manually)
 *  - surfaces "dead link" as an `error` event once `xmit >= deadLink` for any segment
 *
 * It assumes the carrier preserves segment boundaries (as Snowflake's encapsulation
 * framing does). It is intentionally smaller than xtaci/kcp-go — no congestion
 * control, no FEC, no fast-retransmit — because Snowflake's carrier characteristics
 * do not require them, but RTO-based retransmission is essential for recovery when
 * the server's turbotunnel QueuePacketConn drops packets under load.
 */
export class MinimalKcpSession {
  readonly conv: number;
  readonly wnd: number;
  readonly mss: number;
  private readonly now: () => number;
  private readonly rtoInitial: number;
  private readonly rtoMax: number;
  private readonly deadLink: number;
  private readonly flushIntervalMs: number;
  private readonly setTimer: (cb: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private sink?: KcpPacketSink;

  private sendSn = 0;
  private recvNext = 0;
  /** The next sn the peer expects from us (their `una`). Everything below is ACKed. */
  private peerUna = 0;
  /** Pending unsent bytes; stream mode coalesces across write() calls. */
  private sndQueue: Uint8Array[] = [];
  private sndQueueBytes = 0;
  /** Segments in flight: sn -> Unacked. */
  private readonly sndBuf = new Map<number, Unacked>();

  private readonly rx = new ByteQueue();
  /** Out-of-order inbound segments, keyed by sn. */
  private readonly rxBuf = new Map<number, Uint8Array>();

  private closed = false;
  private lastError: Error | undefined;
  private errorListeners: Array<(err: Error) => void> = [];
  private autoFlushHandle: unknown;
  /**
   * True between the first write() of a microtask batch and the microtask
   * itself running. Multiple synchronous writes in the same batch all append
   * to sndQueue; a single flush() call drains them into coalesced segments.
   */
  private flushScheduled = false;

  constructor(opts: KcpSessionOptions) {
    this.conv = opts.conv >>> 0;
    this.wnd = (opts.wnd ?? 65535) >>> 0;
    this.mss = (opts.mss ?? 1200) >>> 0;
    this.now = opts.now ?? (() => Date.now());
    this.rtoInitial = opts.rtoInitial ?? DEFAULT_RTO_INITIAL;
    this.rtoMax = opts.rtoMax ?? DEFAULT_RTO_MAX;
    this.deadLink = opts.deadLink ?? DEFAULT_DEAD_LINK;
    this.flushIntervalMs = opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL;
    this.setTimer =
      opts.setTimer ??
      ((cb, ms) => {
        const h = setInterval(cb, ms);
        (h as unknown as { unref?: () => void }).unref?.();
        return h;
      });
    this.clearTimer =
      opts.clearTimer ?? ((h) => clearInterval(h as ReturnType<typeof setInterval>));
  }

  attachSink(sink: KcpPacketSink): void {
    this.sink = sink;
  }

  onError(listener: (err: Error) => void): void {
    this.errorListeners.push(listener);
  }

  /**
   * Start a periodic flush+retransmit timer. Idempotent. Stop with {@link stopAutoFlush}.
   * Tests that drive time manually should skip this and call {@link update} directly.
   */
  startAutoFlush(): void {
    if (this.autoFlushHandle !== undefined) return;
    this.autoFlushHandle = this.setTimer(() => this.update(), this.flushIntervalMs);
  }

  stopAutoFlush(): void {
    if (this.autoFlushHandle === undefined) return;
    this.clearTimer(this.autoFlushHandle);
    this.autoFlushHandle = undefined;
  }

  close(err?: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.lastError = err;
    this.stopAutoFlush();
    this.rx.close();
  }

  /**
   * Feed an incoming KCP "packet" (which may contain multiple concatenated segments).
   */
  inputPacket(pkt: Uint8Array): void {
    if (this.closed) return;
    const segs = decodeKcpSegmentsFromPacket(pkt);
    for (const seg of segs) {
      if (seg.conv >>> 0 !== this.conv) continue;

      // Every segment carries `una` — acknowledge everything strictly below it.
      this.advancePeerUna(seg.una >>> 0);

      switch (seg.cmd) {
        case KCP_CMD.ACK:
          this.sndBuf.delete(seg.sn >>> 0);
          break;
        case KCP_CMD.PUSH:
          this.onPush(seg);
          break;
        case KCP_CMD.WASK:
          this.sendWins();
          break;
        case KCP_CMD.WINS:
          // window probes are informational only; we rely on una/ack.
          break;
        default:
          break;
      }
    }
  }

  /**
   * Queue bytes for reliable delivery. In stream mode, consecutive writes coalesce
   * into the same segment until MSS is reached.
   */
  write(data: Uint8Array): void {
    if (this.closed) throw new Error('session closed');
    if (data.byteLength === 0) return;
    this.sndQueue.push(data);
    this.sndQueueBytes += data.byteLength;
    // Batch within the current microtask so synchronous writes coalesce.
    // Any `await` or `readExactly` below us yields the microtask queue and
    // drives the flush before a caller observes "nothing sent".
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    queueMicrotask(() => {
      this.flushScheduled = false;
      if (!this.closed) this.flush();
    });
  }

  async readExactly(n: number): Promise<Uint8Array> {
    if (this.closed && this.lastError) throw this.lastError;
    await this.rx.waitForAtLeast(n);
    return this.rx.readExactly(n);
  }

  async readSome(n: number): Promise<Uint8Array> {
    if (this.closed && this.lastError) throw this.lastError;
    await this.rx.waitForAtLeast(1);
    const take = Math.min(n, this.rx.length);
    return this.rx.readExactly(take);
  }

  /**
   * Flush queued data into PUSH segments (coalescing up to MSS) and retransmit
   * any segment whose resendts has passed. Returns the number of packets sent.
   */
  update(): number {
    if (this.closed) return 0;
    return this.flush();
  }

  /** Count of segments still awaiting ACK (exposed for tests / backpressure). */
  get inflight(): number {
    return this.sndBuf.size;
  }

  /** Number of bytes queued but not yet turned into a segment. */
  get pending(): number {
    return this.sndQueueBytes;
  }

  private flush(): number {
    if (!this.sink) throw new Error('no sink attached');
    let emitted = 0;
    const now = this.now() >>> 0;

    // Step 1: drain sndQueue into MSS-sized PUSH segments.
    while (this.sndQueueBytes > 0) {
      const take = Math.min(this.mss, this.sndQueueBytes);
      const chunk = this.takeFromQueue(take);
      const sn = this.sendSn >>> 0;
      this.sendSn = (this.sendSn + 1) >>> 0;
      const seg: KcpSegment = {
        conv: this.conv,
        cmd: KCP_CMD.PUSH,
        frg: 0,
        wnd: this.wnd,
        ts: now,
        sn,
        una: this.recvNext >>> 0,
        data: chunk,
      };
      this.sndBuf.set(sn, {
        seg,
        firstSentAt: now,
        resendts: (now + this.rtoInitial) >>> 0,
        rto: this.rtoInitial,
        xmit: 1,
      });
      this.sink(encodeKcpSegment(seg));
      emitted += 1;
    }

    // Step 2: retransmit any unacked segment whose resendts has passed.
    for (const [, entry] of this.sndBuf) {
      if (now >= entry.resendts) {
        // Refresh una on retransmit so the peer can trim its own buffers.
        entry.seg.una = this.recvNext >>> 0;
        entry.seg.ts = now;
        entry.xmit += 1;
        if (entry.xmit > this.deadLink) {
          this.fail(new Error(`kcp: dead link (retransmitted sn=${entry.seg.sn} ${entry.xmit}x)`));
          return emitted;
        }
        entry.rto = Math.min(entry.rto * 2, this.rtoMax);
        entry.resendts = (now + entry.rto) >>> 0;
        this.sink(encodeKcpSegment(entry.seg));
        emitted += 1;
      }
    }

    return emitted;
  }

  private takeFromQueue(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const head = this.sndQueue[0]!;
      const take = Math.min(head.byteLength, n - off);
      out.set(head.subarray(0, take), off);
      off += take;
      if (take === head.byteLength) {
        this.sndQueue.shift();
      } else {
        this.sndQueue[0] = head.subarray(take);
      }
    }
    this.sndQueueBytes -= n;
    return out;
  }

  private advancePeerUna(una: number): void {
    // Anything in sndBuf with sn < una has been received by the peer.
    if (((una - this.peerUna) | 0) > 0) this.peerUna = una;
    for (const sn of this.sndBuf.keys()) {
      if (((sn - una) | 0) < 0) this.sndBuf.delete(sn);
    }
  }

  private onPush(seg: KcpSegment): void {
    const sn = seg.sn >>> 0;
    // Always ACK, even duplicates — the peer may not have seen our previous ACK.
    this.sendAck(seg);
    const delta = (sn - this.recvNext) | 0;
    if (delta < 0) {
      // Duplicate we already delivered.
      return;
    }
    if (delta === 0) {
      this.rx.push(seg.data.slice());
      this.recvNext = (this.recvNext + 1) >>> 0;
      // Drain any buffered, now-contiguous segments.
      while (this.rxBuf.has(this.recvNext)) {
        const buffered = this.rxBuf.get(this.recvNext)!;
        this.rxBuf.delete(this.recvNext);
        this.rx.push(buffered);
        this.recvNext = (this.recvNext + 1) >>> 0;
      }
      return;
    }
    // Out-of-order: buffer until its predecessors arrive.
    if (!this.rxBuf.has(sn)) this.rxBuf.set(sn, seg.data.slice());
  }

  private sendAck(seg: KcpSegment): void {
    if (!this.sink) return;
    const ack: KcpSegment = {
      conv: this.conv,
      cmd: KCP_CMD.ACK,
      frg: 0,
      wnd: this.wnd,
      ts: seg.ts >>> 0,
      sn: seg.sn >>> 0,
      una: this.recvNext >>> 0,
      data: new Uint8Array(0),
    };
    this.sink(encodeKcpSegment(ack));
  }

  private sendWins(): void {
    if (!this.sink) return;
    const wins: KcpSegment = {
      conv: this.conv,
      cmd: KCP_CMD.WINS,
      frg: 0,
      wnd: this.wnd,
      ts: this.now() >>> 0,
      sn: 0,
      una: this.recvNext >>> 0,
      data: new Uint8Array(0),
    };
    this.sink(encodeKcpSegment(wins));
  }

  private fail(err: Error): void {
    this.close(err);
    for (const l of this.errorListeners) {
      try {
        l(err);
      } catch {
        // swallow listener errors
      }
    }
  }
}
