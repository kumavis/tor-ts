/**
 * Complete Snowflake WebRTC stack.
 *
 * Combines:
 * - WebRTC downlink (via broker signaling)
 * - KCP reliable transport layer
 * - SMUX multiplexing
 *
 * This is the WebRTC equivalent of SnowflakeWsStack.
 */

import crypto from 'node:crypto';
import { once } from 'node:events';
import { SnowflakeWebRtcDownlink } from './webrtc-downlink.ts';
import type { SnowflakeWebRtcDownlinkOptions } from './webrtc-downlink.ts';
import { MinimalKcpSession } from './kcp/session.ts';
import { SmuxSession, SmuxStream } from './smux/session.ts';

export type SnowflakeWebRtcStackOptions = SnowflakeWebRtcDownlinkOptions;

/**
 * Complete Snowflake WebRTC connection stack.
 *
 * Usage:
 * ```typescript
 * const stack = new SnowflakeWebRtcStack();
 * await stack.connect();
 * const stream = await stack.openStream();
 * // Use stream for reading/writing
 * ```
 */
export class SnowflakeWebRtcStack {
  readonly downlink: SnowflakeWebRtcDownlink;
  readonly kcp: MinimalKcpSession;
  readonly smux: SmuxSession;

  constructor(opts: SnowflakeWebRtcStackOptions = {}) {
    this.downlink = new SnowflakeWebRtcDownlink(opts);

    // Mirror kcp-go NewConn2: random conv.
    const conv = crypto.randomBytes(4).readUInt32LE(0);
    this.kcp = new MinimalKcpSession({ conv });

    this.smux = new SmuxSession(
      {
        readExactly: (n) => this.kcp.readExactly(n),
        write: (d) => this.kcp.write(d),
      },
      { isClient: true, ver: 2, maxStreamBuffer: 1024 * 1024 }
    );
  }

  /**
   * Connect to the Snowflake network via WebRTC.
   * This initiates broker signaling, WebRTC connection,
   * and sets up the KCP/SMUX layers.
   */
  async connect(): Promise<void> {
    await this.downlink.connect();

    // Wire: downlink packets -> KCP input.
    this.downlink.on('packet', (pkt: Uint8Array) => {
      this.kcp.inputPacket(pkt);
    });

    // Wire: KCP output packets -> downlink.
    this.kcp.attachSink((pkt) => this.downlink.sendPacket(pkt));

    // Surface errors.
    this.downlink.on('error', (err) => this.smux.emit('error', err));
  }

  /**
   * Open a new multiplexed stream.
   */
  async openStream(): Promise<SmuxStream> {
    return await this.smux.openStream();
  }

  /**
   * Close the connection.
   */
  async close(): Promise<void> {
    this.downlink.close();
    await Promise.race([once(this.smux, 'close'), new Promise((r) => setTimeout(r, 10))]);
  }

  /**
   * Check if the connection is active.
   */
  isConnected(): boolean {
    return this.downlink.isConnected();
  }
}
