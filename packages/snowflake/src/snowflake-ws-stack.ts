import crypto from 'node:crypto';
import { once } from 'node:events';
import { SnowflakeWsDownlink } from './ws-downlink.ts';
import { MinimalKcpSession } from './kcp/session.ts';
import { SmuxSession, SmuxStream } from './smux/session.ts';

export type SnowflakeWsStackOptions = {
  relayUrl?: string;
};

export class SnowflakeWsStack {
  readonly relayUrl: string;
  readonly downlink: SnowflakeWsDownlink;
  readonly kcp: MinimalKcpSession;
  readonly smux: SmuxSession;

  constructor(opts: SnowflakeWsStackOptions = {}) {
    this.relayUrl = opts.relayUrl ?? 'wss://snowflake.torproject.net/';
    this.downlink = new SnowflakeWsDownlink({ url: this.relayUrl });

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

  async openStream(): Promise<SmuxStream> {
    return await this.smux.openStream();
  }

  async close(): Promise<void> {
    this.downlink.close();
    await Promise.race([once(this.smux, 'close'), new Promise((r) => setTimeout(r, 10))]);
  }
}
