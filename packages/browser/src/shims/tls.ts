/**
 * Browser shim for node:tls using node-forge.
 * Provides TLS connection capability over arbitrary duplex streams.
 */

import forge from 'node-forge';
import { EventEmitter } from 'events';
import { Duplex } from 'stream';

export interface TLSConnectOptions {
  socket?: Duplex;
  servername?: string;
  rejectUnauthorized?: boolean;
}

export interface DetailedPeerCertificate {
  raw: Buffer;
  subject: Record<string, string>;
  issuer: Record<string, string>;
  valid_from: string;
  valid_to: string;
}

/**
 * TLSSocket implementation using node-forge for browser environments.
 */
export class TLSSocket extends EventEmitter {
  private tls: forge.tls.Connection;
  private underlying: Duplex;
  private connected = false;
  private peerCert: DetailedPeerCertificate | null = null;

  constructor(underlying: Duplex, options: TLSConnectOptions = {}) {
    super();
    this.underlying = underlying;

    // Create forge TLS client connection
    this.tls = forge.tls.createConnection({
      server: false,
      verify: (_connection, verified, _depth, certs) => {
        // Store the peer certificate
        if (certs && certs.length > 0) {
          const cert = certs[0];
          if (cert) {
            const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
            this.peerCert = {
              raw: Buffer.from(der.getBytes(), 'binary'),
              subject: this.formatName(cert.subject),
              issuer: this.formatName(cert.issuer),
              valid_from: cert.validity.notBefore.toISOString(),
              valid_to: cert.validity.notAfter.toISOString(),
            };
          }
        }
        // Accept all certificates (rejectUnauthorized: false behavior)
        if (options.rejectUnauthorized === false) {
          return true;
        }
        return verified;
      },
      connected: (_connection) => {
        this.connected = true;
        this.emit('secureConnect');
      },
      tlsDataReady: (connection) => {
        // Send TLS records to the underlying socket
        const data = connection.tlsData.getBytes();
        if (data.length > 0) {
          this.underlying.write(Buffer.from(data, 'binary'));
        }
      },
      dataReady: (connection) => {
        // Decrypted application data ready
        const data = connection.data.getBytes();
        if (data.length > 0) {
          this.emit('data', Buffer.from(data, 'binary'));
        }
      },
      closed: () => {
        this.emit('close');
      },
      error: (_connection, error) => {
        console.error('[forge-tls] TLS error:', error);
        this.emit('error', new Error(error.message));
      },
    });

    // Set SNI if provided
    if (options.servername) {
      (this.tls as forge.tls.Connection & { virtualHost?: string }).virtualHost =
        options.servername;
    }

    // Wire up underlying socket
    underlying.on('data', (chunk: Buffer) => {
      try {
        console.log('[forge-tls] Received', chunk.length, 'bytes from underlying socket');
        this.tls.process(chunk.toString('binary'));
      } catch (err) {
        console.error('[forge-tls] Error processing TLS data:', err);
        this.emit('error', err);
      }
    });

    underlying.on('error', (err: Error) => {
      this.emit('error', err);
    });

    underlying.on('close', () => {
      this.tls.close();
    });

    // Start TLS handshake
    this.tls.handshake();
  }

  private formatName(name: {
    attributes: Array<{ shortName?: string; name?: string; value?: unknown }>;
  }): Record<string, string> {
    const result: Record<string, string> = {};
    for (const attr of name.attributes) {
      const key = attr.shortName || attr.name || 'unknown';
      result[key] = typeof attr.value === 'string' ? attr.value : '';
    }
    return result;
  }

  write(data: Buffer | string): boolean {
    const bytes = typeof data === 'string' ? data : data.toString('binary');
    try {
      this.tls.prepare(bytes);
      return true;
    } catch (err) {
      this.emit('error', err);
      return false;
    }
  }

  end(): void {
    this.tls.close();
    this.underlying.end();
  }

  destroy(err?: Error): void {
    if (err) {
      this.emit('error', err);
    }
    this.tls.close();
    this.underlying.destroy();
  }

  getPeerCertificate(detailed?: boolean): DetailedPeerCertificate | Record<string, never> {
    if (detailed && this.peerCert) {
      return this.peerCert;
    }
    return this.peerCert || {};
  }

  address(): { port: number; family: string; address: string } {
    // Return dummy address info for browser
    return { port: 0, family: 'IPv4', address: '0.0.0.0' };
  }

  get encrypted(): boolean {
    return this.connected;
  }

  get authorized(): boolean {
    return true; // We're not doing strict verification
  }
}

/**
 * Create a TLS connection over an existing socket/stream.
 */

export function connect(options: TLSConnectOptions): TLSSocket;
// eslint-disable-next-line no-redeclare
export function connect(port: number, host: string, options?: TLSConnectOptions): TLSSocket;
// eslint-disable-next-line no-redeclare
export function connect(
  portOrOptions: number | TLSConnectOptions,
  _hostOrOptions?: string | TLSConnectOptions,
  _maybeOptions?: TLSConnectOptions
): TLSSocket {
  // Handle overloads
  if (typeof portOrOptions === 'object') {
    // connect(options) form
    const options = portOrOptions;
    if (!options.socket) {
      throw new Error('In browser environment, tls.connect requires a socket option');
    }
    return new TLSSocket(options.socket, options);
  }

  // connect(port, host, options) form - not supported in browser without socket
  throw new Error('tls.connect(port, host) is not supported in browser. Use socket option.');
}

export default {
  connect,
  TLSSocket,
};
