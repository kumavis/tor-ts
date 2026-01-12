/**
 * Tor channel connection using Snowflake WebRTC transport.
 *
 * This provides a Tor-compatible channel over WebRTC, enabling:
 * - Domain fronting for censorship resistance
 * - Better NAT traversal via ICE
 * - Reduced "using Tor" signal footprint
 */

import crypto from 'node:crypto';
import tls from 'node:tls';
import type { TLSSocket } from 'node:tls';

import { ChannelConnection } from 'tor/channel';
import type { NodejsPeerAddressInfo } from 'tor/channel';

import { SmuxStreamDuplex } from './smux/duplex.ts';
import { SnowflakeWebRtcStack } from './snowflake-webrtc-stack.ts';
import type { SnowflakeWebRtcStackOptions } from './snowflake-webrtc-stack.ts';

export type SnowflakeWebRtcChannelOptions = SnowflakeWebRtcStackOptions;

/**
 * Tor channel connection that uses Snowflake WebRTC as the carrier.
 *
 * This is the WebRTC equivalent of SnowflakeTlsChannelConnection.
 * Uses the broker to find volunteer proxies and establishes a
 * WebRTC connection for the Tor transport.
 */
export class SnowflakeWebRtcTlsChannelConnection extends ChannelConnection {
  private stack?: SnowflakeWebRtcStack;
  private tlsSocket?: TLSSocket;

  async connect(opts: SnowflakeWebRtcChannelOptions = {}): Promise<void> {
    const stack = new SnowflakeWebRtcStack(opts);
    this.stack = stack;
    await stack.connect();

    const smuxStream = await stack.openStream();
    const streamDuplex = new SmuxStreamDuplex(smuxStream);

    const socket = tls.connect({
      socket: streamDuplex,
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
    });
    this.tlsSocket = socket;

    await new Promise<void>((resolve, reject) => {
      socket.once('secureConnect', resolve);
      socket.once('error', reject);
    });

    socket.on('data', (data) => {
      this.onData(data);
    });

    const dummyAddressInfo: NodejsPeerAddressInfo = {
      address: '0.0.0.0',
      family: 'IPv4',
      port: 0,
    };

    this.peerConnectionDetails = {
      cert: socket.getPeerCertificate(true),
      addressInfo: dummyAddressInfo,
    };

    await this.performHandshake();
  }

  sendData(data: Buffer): void {
    if (!this.tlsSocket) throw new Error('tls socket is undefined');
    this.tlsSocket.write(data);
  }

  override destroy(): void {
    super.destroy();
    this.tlsSocket?.destroy();
    void this.stack?.close();
  }
}

function makeRandomServerName(): string {
  const hex = crypto.randomBytes(Math.floor(Math.random() * 20 + 4)).toString('hex');
  return `www.${hex}.net`;
}
