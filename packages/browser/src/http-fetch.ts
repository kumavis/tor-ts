/**
 * HTTP/1.1 fetch implementation over Tor circuit streams.
 * Manually constructs HTTP requests and parses responses.
 *
 * ARCHITECTURE:
 * For HTTPS URLs, TLS is performed INSIDE the Tor stream (not by the exit node).
 * This matches how Tor works: the exit node opens a raw TCP connection, and
 * the client is responsible for TLS if connecting to port 443.
 *
 * FEATURES:
 * - Automatic redirect following (3xx responses) with configurable max redirects
 * - Supports both HTTP and HTTPS (TLS inside Tor stream for HTTPS)
 *
 * LIMITATIONS:
 * - Responses are decoded as UTF-8 text. Binary responses (images, etc.) will be corrupted.
 *   This is intentional for the HTML-fetching use case. For binary data, use a Buffer-based API.
 * - Only supports HTTP/1.1 with Connection: close semantics.
 */

import type { Circuit, CircuitStream } from 'tor/circuit';
import {
  parseHttpHeaders,
  parseHttpStatusLine,
  decodeChunked,
  isChunkedComplete,
} from 'tor/http-parse';
import { makeTLSClient, setCryptoImplementation } from '@reclaimprotocol/tls';
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto';

// Use the webcrypto implementation for TLS
setCryptoImplementation(webcryptoCrypto);

export interface TorFetchResponse {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: string;
}

/**
 * Interface for a readable/writable transport (either raw stream or TLS-wrapped).
 */
interface Transport {
  write(data: Buffer): void;
  on(event: 'data', listener: (chunk: Buffer) => void): void;
  on(event: 'end', listener: () => void): void;
  on(event: 'error', listener: (err: Error) => void): void;
  removeAllListeners(): void;
  destroy(err?: Error): void;
}

/**
 * Wrap a CircuitStream with TLS, returning a transport that can be used for HTTP.
 * This performs the TLS handshake inside the Tor stream.
 */
async function wrapWithTLS(stream: CircuitStream, host: string): Promise<Transport> {
  return new Promise((resolve, reject) => {
    const dataListeners: Array<(chunk: Buffer) => void> = [];
    const endListeners: Array<() => void> = [];
    const errorListeners: Array<(err: Error) => void> = [];
    // Queue for data that arrives before any listeners are registered
    const pendingDataQueue: Buffer[] = [];
    let handshakeComplete = false;
    let ended = false;
    let endPending = false; // Track if end should be fired when listeners are added
    let rejected = false; // Prevent double-rejection

    const safeReject = (err: Error) => {
      if (!rejected && !handshakeComplete) {
        rejected = true;
        reject(err);
      }
    };

    const tls = makeTLSClient({
      host,
      // For external HTTPS sites, we DO want to verify certificates
      // (unlike Tor relay connections which use self-signed certs)
      verifyServerCertificate: true,

      // Write TLS packets to the Tor stream
      write: async (packet) => {
        const data = Buffer.concat([Buffer.from(packet.header), Buffer.from(packet.content)]);
        await stream.write(data);
      },

      // Handle handshake completion
      onHandshake: () => {
        handshakeComplete = true;
        resolve(transport);
      },

      // Handle decrypted application data
      onApplicationData: (plaintext: Uint8Array) => {
        const buf = Buffer.from(plaintext);
        if (dataListeners.length > 0) {
          for (const listener of dataListeners) {
            listener(buf);
          }
        } else {
          // Queue data if no listeners registered yet
          pendingDataQueue.push(buf);
        }
      },

      // Handle TLS end
      onTlsEnd: (error?: Error) => {
        if (error && !handshakeComplete) {
          safeReject(error);
        } else if (error) {
          for (const listener of errorListeners) {
            listener(error);
          }
        }
        if (!ended) {
          ended = true;
          if (endListeners.length > 0) {
            for (const listener of endListeners) {
              listener();
            }
          } else {
            // Mark that end should be fired when listeners are added
            endPending = true;
          }
        }
      },

      // Ignore certificate events and session tickets
      onRecvCertificates: () => {},
      onSessionTicket: () => {},
    });

    // Queue to serialize TLS processing (handleReceivedBytes is async)
    let processingQueue: Promise<void> = Promise.resolve();

    // Forward data from the Tor stream to the TLS client
    stream.on('data', (chunk: Buffer) => {
      if (!ended) {
        // Chain processing to ensure order and completion
        processingQueue = processingQueue.then(async () => {
          if (!ended) {
            try {
              await tls.handleReceivedBytes(chunk);
            } catch (err) {
              if (!handshakeComplete) {
                safeReject(err as Error);
              } else {
                for (const listener of errorListeners) {
                  listener(err as Error);
                }
              }
            }
          }
        });
      }
    });

    stream.on('end', () => {
      if (!ended) {
        // Wait for any pending TLS processing to complete before firing 'end'
        processingQueue.then(() => {
          if (!ended) {
            ended = true;
            // If handshake not complete, this is an error
            if (!handshakeComplete) {
              safeReject(new Error('Connection closed before TLS handshake completed'));
            }
            if (endListeners.length > 0) {
              for (const listener of endListeners) {
                listener();
              }
            } else {
              endPending = true;
            }
          }
        });
      }
    });

    stream.on('error', (err: Error) => {
      if (!handshakeComplete) {
        safeReject(err);
      } else {
        for (const listener of errorListeners) {
          listener(err);
        }
      }
    });

    // Create the transport interface
    const transport: Transport = {
      write(data: Buffer) {
        if (!ended) {
          tls.write(data).catch((err) => {
            for (const listener of errorListeners) {
              listener(err);
            }
          });
        }
      },
      on: ((event: string, listener: (...args: unknown[]) => void) => {
        if (event === 'data') {
          dataListeners.push(listener as (chunk: Buffer) => void);
          // Flush any queued data to the new listener
          while (pendingDataQueue.length > 0) {
            const data = pendingDataQueue.shift()!;
            (listener as (chunk: Buffer) => void)(data);
          }
        } else if (event === 'end') {
          endListeners.push(listener as () => void);
          // Fire end if it was pending
          if (endPending) {
            endPending = false;
            (listener as () => void)();
          }
        } else if (event === 'error') {
          errorListeners.push(listener as (err: Error) => void);
        }
      }) as Transport['on'],
      removeAllListeners() {
        dataListeners.length = 0;
        endListeners.length = 0;
        errorListeners.length = 0;
        pendingDataQueue.length = 0;
        stream.removeAllListeners();
      },
      destroy(err?: Error) {
        ended = true;
        tls.end().catch(() => {});
        stream.destroy(err);
      },
    };

    // Start the TLS handshake
    tls.startHandshake().catch((err) => {
      if (!handshakeComplete) {
        safeReject(err);
      }
    });
  });
}

/**
 * Create a simple transport wrapper around a raw CircuitStream (for HTTP).
 */
function wrapRawStream(stream: CircuitStream): Transport {
  return {
    write(data: Buffer) {
      stream.write(data).catch((err) => {
        stream.emit('error', err);
      });
    },
    on: ((event: string, listener: (...args: unknown[]) => void) => {
      stream.on(event, listener);
    }) as Transport['on'],
    removeAllListeners() {
      stream.removeAllListeners();
    },
    destroy(err?: Error) {
      stream.destroy(err);
    },
  };
}

export interface FetchViaTorOptions {
  method?: string;
  headers?: Record<string, string>;
  timeout?: number;
  /** Maximum number of redirects to follow. Set to 0 to disable. Default: 10 */
  maxRedirects?: number;
  /** Whether to follow redirects automatically. Default: true */
  followRedirects?: boolean;
}

/**
 * Fetch a URL over a Tor circuit.
 * Supports HTTP and HTTPS (TLS is performed inside the Tor stream for HTTPS).
 * Automatically follows redirects (3xx responses) up to maxRedirects times.
 */
export async function fetchViaTor(
  circuit: Circuit,
  url: string,
  options: FetchViaTorOptions = {}
): Promise<TorFetchResponse> {
  const { followRedirects = true, maxRedirects = 10 } = options;

  return fetchViaTorInternal(circuit, url, options, followRedirects ? maxRedirects : 0);
}

/**
 * Internal fetch implementation with redirect counter.
 */
async function fetchViaTorInternal(
  circuit: Circuit,
  url: string,
  options: FetchViaTorOptions,
  redirectsRemaining: number
): Promise<TorFetchResponse> {
  const parsedUrl = new URL(url);
  const host = parsedUrl.hostname;
  const isHttps = parsedUrl.protocol === 'https:';
  const port = parsedUrl.port || (isHttps ? '443' : '80');
  const path = parsedUrl.pathname + parsedUrl.search;
  const method = options.method || 'GET';

  // Open stream to target
  const target = `${host}:${port}`;
  const stream = circuit.openStream(target);

  // Wait for connection
  await stream.connectionPromiseKit.promise;

  // For HTTPS, wrap with TLS. For HTTP, use raw stream.
  let transport: Transport;
  if (isHttps) {
    transport = await wrapWithTLS(stream, host);
  } else {
    transport = wrapRawStream(stream);
  }

  // Build HTTP request
  const requestHeaders: Record<string, string> = {
    Host: host,
    'User-Agent': 'Mozilla/5.0 (compatible; TorBrowser/1.0)',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    Connection: 'close',
    ...options.headers,
  };

  let request = `${method} ${path || '/'} HTTP/1.1\r\n`;
  for (const [key, value] of Object.entries(requestHeaders)) {
    request += `${key}: ${value}\r\n`;
  }
  request += '\r\n';

  // Send request
  transport.write(Buffer.from(request, 'utf-8'));

  // Read response with timeout
  const timeout = options.timeout || 30000;
  const response = await readHttpResponse(transport, timeout);

  // Handle redirects (3xx status codes)
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get('location');

    if (location && redirectsRemaining > 0) {
      // Resolve relative URLs against the current URL
      const redirectUrl = new URL(location, url).href;

      // For 301, 302, 303: change method to GET (except for HEAD)
      // For 307, 308: preserve the original method
      let redirectMethod = method;
      if (response.status === 301 || response.status === 302 || response.status === 303) {
        if (method !== 'HEAD') {
          redirectMethod = 'GET';
        }
      }

      return fetchViaTorInternal(
        circuit,
        redirectUrl,
        { ...options, method: redirectMethod },
        redirectsRemaining - 1
      );
    } else if (location && redirectsRemaining === 0) {
      throw new Error(
        `Too many redirects (max ${options.maxRedirects ?? 10}). Last redirect: ${location}`
      );
    }
    // If no location header, return the redirect response as-is
  }

  return response;
}

/**
 * Read and parse HTTP response from a transport (raw or TLS-wrapped stream).
 * Uses shared parsing utilities from tor/http-parse.
 */
async function readHttpResponse(transport: Transport, timeout: number): Promise<TorFetchResponse> {
  return new Promise<TorFetchResponse>((resolve, reject) => {
    let data = Buffer.alloc(0);
    let headersComplete = false;
    let status = 0;
    let statusText = '';
    let headers = new Map<string, string>();
    let contentLength = -1;
    let isChunked = false;
    let bodyStart = 0;

    const timeoutId = setTimeout(() => {
      transport.destroy(new Error('Response timeout'));
      reject(new Error('Response timeout'));
    }, timeout);

    const cleanup = () => {
      clearTimeout(timeoutId);
      transport.removeAllListeners();
    };

    transport.on('data', (chunk: Buffer) => {
      data = Buffer.concat([data, chunk]);

      if (!headersComplete) {
        const headerEnd = data.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          headersComplete = true;
          bodyStart = headerEnd + 4;

          const headerSection = data.subarray(0, headerEnd).toString('utf-8');
          const lines = headerSection.split('\r\n');

          // Parse status line using shared utility
          const statusLine = lines[0];
          if (statusLine) {
            const parsed = parseHttpStatusLine(statusLine);
            if (parsed) {
              status = parsed.statusCode;
              statusText = parsed.statusText;
            }
          }

          // Parse headers using shared utility
          headers = parseHttpHeaders(headerSection);

          // Check for content-length or chunked
          const cl = headers.get('content-length');
          if (cl) {
            contentLength = parseInt(cl, 10);
          }
          isChunked = headers.get('transfer-encoding')?.toLowerCase() === 'chunked';
        }
      }

      // Check if we have the complete body
      if (headersComplete) {
        const bodyData = data.subarray(bodyStart);

        if (contentLength >= 0 && bodyData.length >= contentLength) {
          cleanup();
          resolve({
            status,
            statusText,
            headers,
            body: bodyData.subarray(0, contentLength).toString('utf-8'),
          });
        } else if (isChunked) {
          // Check for final chunk using shared utility
          const bodyStr = bodyData.toString('utf-8');
          if (isChunkedComplete(bodyStr)) {
            cleanup();
            resolve({
              status,
              statusText,
              headers,
              body: decodeChunked(bodyData),
            });
          }
        }
      }
    });

    transport.on('end', () => {
      cleanup();
      if (headersComplete) {
        const bodyData = data.subarray(bodyStart);
        resolve({
          status,
          statusText,
          headers,
          body: isChunked ? decodeChunked(bodyData) : bodyData.toString('utf-8'),
        });
      } else {
        reject(new Error('Connection closed before headers complete'));
      }
    });

    transport.on('error', (err: Error) => {
      cleanup();
      reject(err);
    });
  });
}

/**
 * Simple helper to fetch HTML content.
 */
export async function fetchHtml(circuit: Circuit, url: string): Promise<string> {
  const response = await fetchViaTor(circuit, url, {
    headers: {
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
  });

  if (response.status >= 400) {
    throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
  }

  return response.body;
}
