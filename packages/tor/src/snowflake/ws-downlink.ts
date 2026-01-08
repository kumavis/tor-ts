import WebSocket from 'ws';
import { EventEmitter } from 'node:events';
import { EncapsulationDecoder, encodeEncapsulatedData } from './encapsulation.ts';
import type { ClientId } from './turbotunnel.ts';
import { buildTurbotunnelPreamble, newClientId } from './turbotunnel.ts';

export type SnowflakeWsDownlinkOptions = {
  url: string;
  clientId?: ClientId;
};

/**
 * Minimal Snowflake "downlink" client:
 * - connects to Snowflake server WebSocket (relay URL)
 * - sends turbotunnel token + clientID prefix
 * - exposes encapsulated "packets" as events (these packets are KCP datagrams)
 */
export class SnowflakeWsDownlink extends EventEmitter {
  readonly url: string;
  readonly clientId: ClientId;
  private ws?: WebSocket;
  private readonly dec = new EncapsulationDecoder();

  constructor(opts: SnowflakeWsDownlinkOptions) {
    super();
    this.url = opts.url;
    this.clientId = opts.clientId ?? newClientId();
  }

  async connect(): Promise<void> {
    if (this.ws) throw new Error('already connected');

    const ws = new WebSocket(this.url, { perMessageDeflate: false });
    ws.binaryType = 'arraybuffer';
    this.ws = ws;

    ws.on('message', (data: WebSocket.RawData) => {
      const chunk = rawDataToUint8Array(data);

      this.dec.push(chunk);
      for (;;) {
        const pkt = this.dec.popData();
        if (!pkt) break;
        this.emit('packet', pkt);
      }
    });

    ws.on('close', () => {
      this.emit('close');
    });
    ws.on('error', (err: Error) => {
      this.emit('error', err);
    });

    await new Promise<void>((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });

    // Enter turbotunnel mode.
    ws.send(buildTurbotunnelPreamble(this.clientId));
  }

  sendPacket(pkt: Uint8Array): void {
    if (!this.ws) throw new Error('not connected');
    this.ws.send(encodeEncapsulatedData(pkt));
  }

  close(): void {
    if (!this.ws) return;
    // Try to flush decoder state (if caller cares they can listen for 'error').
    try {
      this.dec.finish();
    } catch {
      // ignore
    }
    this.ws.close();
  }
}

function rawDataToUint8Array(data: WebSocket.RawData): Uint8Array {
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return Uint8Array.from(Buffer.concat(data));
  if (ArrayBuffer.isView(data))
    return Uint8Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  // Buffer
  return Uint8Array.from(data);
}

