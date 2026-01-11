/**
 * HTTP/1.1 fetch implementation over Tor circuit streams.
 * Manually constructs HTTP requests and parses responses.
 *
 * LIMITATIONS:
 * - Responses are decoded as UTF-8 text. Binary responses (images, etc.) will be corrupted.
 *   This is intentional for the HTML-fetching use case. For binary data, use a Buffer-based API.
 * - HTTP redirects (3xx) are NOT followed automatically. Callers must handle redirects
 *   if needed (e.g., http→https, www→non-www).
 * - Only supports HTTP/1.1 with Connection: close semantics.
 */

import type { Circuit, CircuitStream } from 'tor/circuit';
import {
  parseHttpHeaders,
  parseHttpStatusLine,
  decodeChunked,
  isChunkedComplete,
} from 'tor/http-parse';

export interface TorFetchResponse {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: string;
}

/**
 * Fetch a URL over a Tor circuit.
 * Supports HTTP and HTTPS (TLS is handled by the exit node).
 *
 * Note: Does not follow redirects. Check response.status for 3xx codes
 * and handle manually if redirect-following is needed.
 */
export async function fetchViaTor(
  circuit: Circuit,
  url: string,
  options: { method?: string; headers?: Record<string, string>; timeout?: number } = {}
): Promise<TorFetchResponse> {
  const parsedUrl = new URL(url);
  const host = parsedUrl.hostname;
  const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
  const path = parsedUrl.pathname + parsedUrl.search;
  const method = options.method || 'GET';

  // Open stream to target
  const target = `${host}:${port}`;
  const stream = circuit.openStream(target);

  // Wait for connection
  await stream.connectionPromiseKit.promise;

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
  await stream.write(Buffer.from(request, 'utf-8'));

  // Read response with timeout
  const timeout = options.timeout || 30000;
  const response = await readHttpResponse(stream, timeout);

  return response;
}

/**
 * Read and parse HTTP response from a circuit stream.
 * Uses shared parsing utilities from tor/http-parse.
 */
async function readHttpResponse(stream: CircuitStream, timeout: number): Promise<TorFetchResponse> {
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
      stream.destroy(new Error('Response timeout'));
      reject(new Error('Response timeout'));
    }, timeout);

    const cleanup = () => {
      clearTimeout(timeoutId);
      stream.removeAllListeners();
    };

    stream.on('data', (chunk: Buffer) => {
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

    stream.on('end', () => {
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

    stream.on('error', (err: Error) => {
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
