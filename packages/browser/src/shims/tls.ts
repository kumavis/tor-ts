/**
 * Browser TLS shim using @reclaimprotocol/tls.
 *
 * Provides TLS 1.3 support for browser environments over arbitrary duplex streams.
 * Modern Tor relays require TLS 1.3, which this implementation fully supports.
 *
 * Key features:
 * - Pure JavaScript TLS 1.3 implementation (no WASM required)
 * - Uses WebCrypto for cryptographic operations where available
 * - Provides Node.js-compatible TLS socket interface
 * - Extracts raw DER certificates for Tor CERTS cell verification
 */

import { makeTLSClient, setCryptoImplementation } from '@reclaimprotocol/tls';
import type { TLSClientOptions, TLSSessionTicket, X509Certificate } from '@reclaimprotocol/tls';
import { pureJsCrypto } from '@reclaimprotocol/tls/purejs-crypto';
import { EventEmitter } from 'events';
import { Duplex } from 'stream';

// Initialize crypto implementation with browser-compatible random
const cryptoImpl = {
  ...pureJsCrypto,
  randomBytes: (length: number): Uint8Array => {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  },
};
setCryptoImplementation(cryptoImpl);

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
 * TLSSocket implementation using @reclaimprotocol/tls for browser environments.
 * Supports TLS 1.3 which is required by modern Tor relays.
 */
export class TLSSocket extends EventEmitter {
  private underlying: Duplex;
  private connected = false;
  private peerCert: DetailedPeerCertificate | null = null;
  private tls: ReturnType<typeof makeTLSClient> | null = null;
  private handshakePromise: Promise<void> | null = null;
  private ended = false;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(underlying: Duplex, options: TLSConnectOptions = {}) {
    super();
    this.underlying = underlying;

    // Start handshake asynchronously
    this.handshakePromise = this.performHandshake(options).catch((err) => {
      this.emit('error', err);
    });
  }

  private async performHandshake(options: TLSConnectOptions): Promise<void> {
    const servername = options.servername || 'localhost';

    return new Promise<void>((resolve, reject) => {
      let handshakeComplete = false;

      // Create TLS client
      const tlsOptions: TLSClientOptions = {
        host: servername,
        // Note: For Tor, certificate verification is intentionally disabled.
        // Tor relays use self-signed certificates; authentication happens at
        // the Tor protocol level via the CERTS cell and RSA/Ed25519 identity verification.
        verifyServerCertificate: options.rejectUnauthorized === true,

        // Write TLS packets to underlying socket
        write: async (packet) => {
          const data = Buffer.concat([Buffer.from(packet.header), Buffer.from(packet.content)]);
          this.underlying.write(data);
        },

        // Handle handshake completion
        onHandshake: () => {
          this.connected = true;
          handshakeComplete = true;
          console.log('[reclaim-tls] TLS handshake completed');
          this.emit('secureConnect');
          resolve();
        },

        // Handle received certificates
        onRecvCertificates: ({ certificates }: { certificates: X509Certificate[] }) => {
          if (certificates.length > 0) {
            const cert = certificates[0];
            try {
              // Access the internal @peculiar/x509 certificate to get raw DER data
              // This is needed for Tor's certificate verification (CERTS cell)
              const internalCert = cert.internal as {
                rawData?: ArrayBuffer;
                notBefore?: Date;
                notAfter?: Date;
              };

              // Extract certificate info
              const cn = cert.getSubjectField('CN');
              const rawData = internalCert.rawData
                ? Buffer.from(internalCert.rawData)
                : Buffer.from(cert.serialiseToPem(), 'utf-8');

              this.peerCert = {
                raw: rawData,
                subject: { CN: cn[0] || '' },
                issuer: {},
                valid_from: internalCert.notBefore?.toISOString() || new Date().toISOString(),
                valid_to: internalCert.notAfter?.toISOString() || new Date().toISOString(),
              };
              console.log('[reclaim-tls] Got peer certificate, raw length:', rawData.length);
            } catch (e) {
              console.warn('[reclaim-tls] Error parsing certificate:', e);
            }
          }
        },

        // Handle application data
        onApplicationData: (plaintext: Uint8Array) => {
          this.emit('data', Buffer.from(plaintext));
        },

        // Handle TLS end
        onTlsEnd: (error?: Error) => {
          if (error && !handshakeComplete) {
            reject(error);
          } else if (error) {
            this.emit('error', error);
          }
          if (!this.ended) {
            this.ended = true;
            this.emit('close');
          }
        },

        // Handle session tickets (for resumption, not currently used)
        onSessionTicket: (_ticket: TLSSessionTicket) => {
          // Could store for session resumption
        },
      };

      this.tls = makeTLSClient(tlsOptions);

      // Handle data from underlying socket
      this.underlying.on('data', async (chunk: Buffer) => {
        if (this.tls && !this.ended) {
          try {
            await this.tls.handleReceivedBytes(chunk);
          } catch (err) {
            if (!handshakeComplete) {
              reject(err as Error);
            } else {
              this.emit('error', err);
            }
          }
        }
      });

      this.underlying.on('error', (err: Error) => {
        if (!handshakeComplete) {
          reject(err);
        } else {
          this.emit('error', err);
        }
      });

      this.underlying.on('close', () => {
        if (!this.ended) {
          this.ended = true;
          this.emit('close');
        }
      });

      // Start the handshake (sends ClientHello)
      this.tls.startHandshake().catch((err) => {
        if (!handshakeComplete) {
          reject(err);
        } else {
          this.emit('error', err);
        }
      });
    });
  }

  /**
   * Write data to the TLS socket.
   * This is synchronous to match Node.js TLS interface, but internally queues async operations.
   * Writes are serialized to ensure proper TLS record ordering.
   */
  write(data: Buffer | string): boolean {
    const bytes = typeof data === 'string' ? Buffer.from(data, 'binary') : data;

    if (this.tls && !this.ended) {
      // Chain writes to ensure they happen in order (TLS record MAC depends on sequence)
      this.writeQueue = this.writeQueue.then(async () => {
        // Wait for handshake to complete if needed
        if (this.handshakePromise) {
          await this.handshakePromise;
        }

        if (this.tls && !this.ended) {
          await this.tls.write(bytes);
        }
      });

      this.writeQueue.catch((err) => {
        this.emit('error', err);
      });

      return true;
    }
    return false;
  }

  async end(): Promise<void> {
    if (this.tls && !this.ended) {
      this.ended = true;
      await this.tls.end();
      this.underlying.end();
    }
  }

  destroy(err?: Error): void {
    if (err) {
      this.emit('error', err);
    }
    this.ended = true;
    if (this.tls) {
      // Best effort end
      this.tls.end().catch(() => {});
    }
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
    return true; // We're not doing strict verification for Tor
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
