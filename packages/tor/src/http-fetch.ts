/**
 * Node.js HTTP/1.1 fetch implementation over Tor circuit streams.
 *
 * For HTTPS, TLS is performed INSIDE the Tor stream using Node's tls module.
 * The exit node only sees encrypted traffic to the destination.
 */

import * as tls from 'node:tls';
import { Duplex } from 'node:stream';
import type { Circuit, CircuitStream } from './circuit.ts';
import {
  parseHttpHeaders,
  parseHttpStatusLine,
  decodeChunked,
  isChunkedComplete,
} from './http-parse.ts';
import type { FetchResponse, FetchOptions } from './client.ts';

/**
 * Internal transport interface for HTTP communication.
 */
interface Transport {
  write(data: Buffer): void;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeAllListeners(): void;
  destroy(err?: Error): void;
}

/**
 * Extended options for Node.js fetch.
 */
export interface NodeFetchOptions extends FetchOptions {
  /** Maximum number of redirects to follow. Set to 0 to disable. Default: 10 */
  maxRedirects?: number;
  /** Whether to follow redirects automatically. Default: true */
  followRedirects?: boolean;
}

/**
 * Fetch a URL over a Tor circuit (Node.js implementation).
 *
 * Supports HTTP and HTTPS (TLS is performed inside the Tor stream for HTTPS).
 * Automatically follows redirects (3xx responses) up to maxRedirects times.
 */
export async function fetchViaTorCircuit(
  circuit: Circuit,
  url: string,
  options: NodeFetchOptions = {}
): Promise<FetchResponse> {
  const { followRedirects = true, maxRedirects = 10 } = options;
  return fetchInternal(circuit, url, options, followRedirects ? maxRedirects : 0);
}

/**
 * Internal fetch implementation with redirect counter.
 */
async function fetchInternal(
  circuit: Circuit,
  url: string,
  options: NodeFetchOptions,
  redirectsRemaining: number
): Promise<FetchResponse> {
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
    'User-Agent': 'Mozilla/5.0 (compatible; TorClient/1.0)',
    Accept: '*/*',
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

      // Clean up current transport
      transport.removeAllListeners();
      transport.destroy();

      // Follow redirect
      return fetchInternal(circuit, redirectUrl, options, redirectsRemaining - 1);
    }
  }

  return response;
}

/**
 * Wrap a circuit stream with Node.js TLS.
 */
async function wrapWithTLS(stream: CircuitStream, hostname: string): Promise<Transport> {
  // Create a duplex stream adapter for the circuit stream
  const duplex = new Duplex({
    read() {
      // Data is pushed via stream.on('data')
    },
    write(chunk: Buffer, _encoding, callback) {
      stream.write(chunk).then(
        () => callback(),
        (err) => callback(err)
      );
    },
  });

  // Forward data from circuit stream to duplex
  stream.on('data', (data: Buffer) => {
    duplex.push(data);
  });

  stream.on('end', () => {
    duplex.push(null);
  });

  // Create TLS connection over the duplex stream
  const tlsSocket = tls.connect({
    socket: duplex as unknown as import('node:net').Socket,
    servername: hostname,
    rejectUnauthorized: true,
  });

  // Wait for TLS handshake
  await new Promise<void>((resolve, reject) => {
    tlsSocket.once('secureConnect', resolve);
    tlsSocket.once('error', reject);
  });

  return {
    write: (data: Buffer) => tlsSocket.write(data),
    on: (event: string, listener: (...args: unknown[]) => void) => {
      tlsSocket.on(event, listener);
    },
    removeAllListeners: () => tlsSocket.removeAllListeners(),
    destroy: (err?: Error) => {
      if (err) tlsSocket.destroy(err);
      else tlsSocket.destroy();
    },
  };
}

/**
 * Wrap a raw circuit stream as a transport.
 */
function wrapRawStream(stream: CircuitStream): Transport {
  return {
    write: (data: Buffer) => {
      stream.write(data);
    },
    on: (event: string, listener: (...args: unknown[]) => void) => {
      stream.on(event, listener);
    },
    removeAllListeners: () => stream.removeAllListeners(),
    destroy: () => stream.destroy(),
  };
}

/**
 * Read a complete HTTP response from a transport.
 */
async function readHttpResponse(transport: Transport, timeoutMs: number): Promise<FetchResponse> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let headersParsed = false;
    let contentLength: number | null = null;
    let isChunked = false;
    let headersEndIndex = -1;

    const timeout = setTimeout(() => {
      transport.removeAllListeners();
      reject(new Error(`HTTP response timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timeout);
      transport.removeAllListeners();
    };

    const checkComplete = () => {
      const buffer = Buffer.concat(chunks);

      // Find headers end
      if (!headersParsed) {
        headersEndIndex = buffer.indexOf('\r\n\r\n');
        if (headersEndIndex === -1) return false;

        const headerSection = buffer.subarray(0, headersEndIndex).toString('utf-8');
        const headers = parseHttpHeaders(headerSection);

        // Determine body framing
        const contentLengthHeader = headers.get('content-length');
        const transferEncoding = headers.get('transfer-encoding');

        if (contentLengthHeader) {
          contentLength = parseInt(contentLengthHeader, 10);
        }
        isChunked = transferEncoding?.toLowerCase().includes('chunked') ?? false;

        headersParsed = true;
      }

      const bodyStart = headersEndIndex + 4;
      const bodyBuffer = buffer.subarray(bodyStart);

      // Check if body is complete
      if (isChunked) {
        if (!isChunkedComplete(bodyBuffer.toString('utf-8'))) {
          return false;
        }
      } else if (contentLength !== null) {
        if (bodyBuffer.length < contentLength) {
          return false;
        }
      }
      // For Connection: close without Content-Length, we need to wait for 'end'

      return true;
    };

    const parseResponse = (): FetchResponse => {
      const buffer = Buffer.concat(chunks);
      const headerSection = buffer.subarray(0, headersEndIndex).toString('utf-8');
      const bodyBuffer = buffer.subarray(headersEndIndex + 4);

      const statusLine = headerSection.split('\r\n')[0] ?? '';
      const parsed = parseHttpStatusLine(statusLine);
      if (!parsed) {
        throw new Error(`Failed to parse HTTP status line: ${statusLine}`);
      }

      const headers = parseHttpHeaders(headerSection);

      let body: string;
      if (isChunked) {
        body = decodeChunked(bodyBuffer.toString('utf-8'));
      } else if (contentLength !== null) {
        body = bodyBuffer.subarray(0, contentLength).toString('utf-8');
      } else {
        body = bodyBuffer.toString('utf-8');
      }

      return {
        status: parsed.statusCode,
        statusText: parsed.statusText,
        headers,
        body,
      };
    };

    transport.on('data', ((chunk: Buffer) => {
      chunks.push(chunk);
      if (checkComplete()) {
        cleanup();
        try {
          resolve(parseResponse());
        } catch (err) {
          reject(err);
        }
      }
    }) as (...args: unknown[]) => void);

    transport.on('end', (() => {
      cleanup();
      try {
        // For Connection: close, the response is complete when stream ends
        if (!headersParsed) {
          const buffer = Buffer.concat(chunks);
          headersEndIndex = buffer.indexOf('\r\n\r\n');
          if (headersEndIndex === -1) {
            reject(new Error('Incomplete HTTP response: no headers'));
            return;
          }
          headersParsed = true;
        }
        resolve(parseResponse());
      } catch (err) {
        reject(err);
      }
    }) as (...args: unknown[]) => void);

    transport.on('error', ((err: Error) => {
      cleanup();
      reject(err);
    }) as (...args: unknown[]) => void);
  });
}
