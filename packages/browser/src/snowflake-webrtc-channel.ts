/**
 * Browser-compatible Snowflake Tor channel using WebRTC transport.
 *
 * This provides better censorship resistance than WebSocket transport:
 * - Domain fronting via the Snowflake broker
 * - Natural NAT traversal via ICE/STUN
 * - Reduced "using Tor" signal footprint
 *
 * Uses TLS 1.3 which is required by modern Tor relays.
 */

import { ChannelConnection } from 'tor/channel';
import type { NodejsPeerAddressInfo } from 'tor/channel';
import { SnowflakeWebRtcStack } from 'snowflake';
import type { SnowflakeWebRtcStackOptions } from 'snowflake';
import { SmuxStreamDuplex } from './shims/smux-duplex.ts';
import { connect as tlsConnect, type TLSSocket } from './shims/tls.ts';

export type SnowflakeWebRtcBrowserChannelOptions = SnowflakeWebRtcStackOptions;

/**
 * Generate a random server name for TLS SNI.
 */
function makeRandomServerName(): string {
  const array = new Uint8Array(Math.floor(Math.random() * 20 + 4));
  crypto.getRandomValues(array);
  const hex = Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `www.${hex}.net`;
}

/**
 * Browser-compatible Tor channel using Snowflake WebRTC transport.
 *
 * This is the browser equivalent of SnowflakeWebRtcTlsChannelConnection.
 * Uses the native browser RTCPeerConnection API for WebRTC.
 */
export class SnowflakeWebRtcBrowserChannel extends ChannelConnection {
  private stack?: SnowflakeWebRtcStack;
  private tlsSocket?: TLSSocket;

  async connect(opts: SnowflakeWebRtcBrowserChannelOptions = {}): Promise<void> {
    const stack = new SnowflakeWebRtcStack(opts);
    this.stack = stack;
    await stack.connect();

    const smuxStream = await stack.openStream();
    const streamDuplex = new SmuxStreamDuplex(smuxStream);

    // Note: rejectUnauthorized: false is intentional and safe here.
    // Tor does NOT use CA-signed certificates. Instead, relay identity is verified
    // cryptographically via the RSA fingerprint during the Tor handshake (CERTS cell).
    // The TLS layer provides encryption; authentication happens at the Tor protocol level.
    const socket = tlsConnect({
      socket: streamDuplex,
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
    });
    this.tlsSocket = socket;

    await new Promise<void>((resolve, reject) => {
      socket.once('secureConnect', resolve);
      socket.once('error', reject);
    });

    socket.on('data', (data: Buffer) => {
      this.onData(data);
    });

    const dummyAddressInfo: NodejsPeerAddressInfo = {
      address: '0.0.0.0',
      family: 'IPv4',
      port: 0,
    };

    const peerCert = socket.getPeerCertificate(true);
    this.peerConnectionDetails = {
      // Cast to any to bridge the type gap between forge and node tls types
      cert: peerCert as unknown as import('tls').DetailedPeerCertificate,
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
