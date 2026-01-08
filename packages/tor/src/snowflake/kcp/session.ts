import { ByteQueue } from './byte-queue.ts';
import { decodeKcpSegmentsFromPacket, encodeKcpSegment, KCP_CMD } from './segment.ts';
import type { KcpSegment } from './segment.ts';

export type KcpPacketSink = (pkt: Uint8Array) => void;

export type KcpSessionOptions = {
  conv: number;
  now?: () => number; // milliseconds
  // conservative segment size; can be bumped later
  mss?: number;
  wnd?: number;
};

/**
 * Minimal KCP session intended for running over a reliable carrier (Snowflake WebSocket encapsulation).
 *
 * This is *not* a full KCP implementation: it assumes no loss/reordering at the carrier layer and
 * therefore omits retransmission logic. It implements enough of the KCP wire protocol to interop
 * with kcp-go in "stream mode" for Snowflake.
 */
export class MinimalKcpSession {
  readonly conv: number;
  readonly wnd: number;
  readonly mss: number;
  private readonly now: () => number;
  private sink?: KcpPacketSink;

  private sendSn = 0;
  private recvNext = 0;
  private unacked = new Map<number, KcpSegment>();

  private readonly rx = new ByteQueue();

  constructor(opts: KcpSessionOptions) {
    this.conv = opts.conv >>> 0;
    this.wnd = (opts.wnd ?? 65535) >>> 0;
    this.mss = (opts.mss ?? 1200) >>> 0;
    this.now = opts.now ?? (() => Date.now());
  }

  attachSink(sink: KcpPacketSink): void {
    this.sink = sink;
  }

  /**
   * Feed an incoming KCP "packet" (which may contain multiple concatenated segments).
   */
  inputPacket(pkt: Uint8Array): void {
    const segs = decodeKcpSegmentsFromPacket(pkt);
    for (const seg of segs) {
      if (seg.conv >>> 0 !== this.conv) continue;
      switch (seg.cmd) {
        case KCP_CMD.ACK:
          // ACK a single serial.
          this.unacked.delete(seg.sn >>> 0);
          break;
        case KCP_CMD.PUSH:
          this.onPush(seg);
          break;
        case KCP_CMD.WASK:
          this.sendWins();
          break;
        case KCP_CMD.WINS:
          // ignore (we don't do congestion/flow control at KCP layer here)
          break;
        default:
          // ignore unknown commands
          break;
      }
    }
  }

  /**
   * Write bytes into the KCP stream (stream mode). This becomes one or more PUSH segments.
   */
  write(data: Uint8Array): void {
    if (!this.sink) throw new Error('no sink attached');
    let off = 0;
    while (off < data.byteLength) {
      const take = Math.min(this.mss, data.byteLength - off);
      const frag = data.subarray(off, off + take);
      off += take;

      const sn = this.sendSn >>> 0;
      this.sendSn = (this.sendSn + 1) >>> 0;

      const seg: KcpSegment = {
        conv: this.conv,
        cmd: KCP_CMD.PUSH,
        frg: 0,
        wnd: this.wnd,
        ts: this.now() >>> 0,
        sn,
        una: this.recvNext >>> 0,
        data: frag,
      };
      this.unacked.set(sn, seg);
      this.sink(encodeKcpSegment(seg));
    }
  }

  /**
   * Read exactly n bytes from the stream (waits until available).
   */
  async readExactly(n: number): Promise<Uint8Array> {
    await this.rx.waitForAtLeast(n);
    return this.rx.readExactly(n);
  }

  /**
   * Read up to n bytes from the stream (waits until at least 1 byte is available).
   */
  async readSome(n: number): Promise<Uint8Array> {
    await this.rx.waitForAtLeast(1);
    const take = Math.min(n, this.rx.length);
    return this.rx.readExactly(take);
  }

  private onPush(seg: KcpSegment): void {
    // In a reliable in-order carrier, we mostly see seg.sn == recvNext.
    const sn = seg.sn >>> 0;
    if (sn < this.recvNext >>> 0) {
      // duplicate; still ACK it
      this.sendAck(seg);
      return;
    }
    if (sn !== this.recvNext >>> 0) {
      // Out-of-order. Minimal implementation: ignore data but still ACK to avoid stalling.
      this.sendAck(seg);
      return;
    }
    // In-order.
    this.rx.push(seg.data.slice());
    this.recvNext = (this.recvNext + 1) >>> 0;
    this.sendAck(seg);
  }

  private sendAck(seg: KcpSegment): void {
    if (!this.sink) return;
    const ack: KcpSegment = {
      conv: this.conv,
      cmd: KCP_CMD.ACK,
      frg: 0,
      wnd: this.wnd,
      // In KCP, ACK.ts is the timestamp of the segment being acked.
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
}
