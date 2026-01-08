import tls from 'node:tls';
import type { TLSSocket } from 'node:tls';
import { ChannelConnection, type NodejsPeerAddressInfo } from '../channel.ts';
import { makeRandomServerName } from '../tls.ts';
import { SnowflakeWsStack } from 'snowflake';
import { SmuxStreamDuplex } from 'snowflake/smux';

export type SnowflakeTlsChannelOptions = {
  relayUrl?: string;
};

/**
 * Tor-specific ChannelConnection that uses the `snowflake` workspace package
 * as its underlying carrier.
 */
export class SnowflakeTlsChannelConnection extends ChannelConnection {
  private stack?: SnowflakeWsStack;
  private tlsSocket?: TLSSocket;

  async connect(opts: SnowflakeTlsChannelOptions = {}): Promise<void> {
    const relayUrl = opts.relayUrl ?? 'wss://snowflake.torproject.net/';

    const stack = new SnowflakeWsStack({ relayUrl });
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
