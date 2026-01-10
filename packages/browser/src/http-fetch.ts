/**
 * HTTP/1.1 fetch implementation over Tor circuit streams.
 * Manually constructs HTTP requests and parses responses.
 */

import type { Circuit, CircuitStream } from 'tor/circuit';

export interface TorFetchResponse {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: string;
}

/**
 * Fetch a URL over a Tor circuit.
 * Supports HTTP and HTTPS (TLS is handled by the exit node).
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
 */
async function readHttpResponse(stream: CircuitStream, timeout: number): Promise<TorFetchResponse> {
  return new Promise<TorFetchResponse>((resolve, reject) => {
    let data = Buffer.alloc(0);
    let headersComplete = false;
    let status = 0;
    let statusText = '';
    const headers = new Map<string, string>();
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

          // Parse status line
          const statusLine = lines[0];
          if (statusLine) {
            const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)/);
            if (match) {
              status = parseInt(match[1]!, 10);
              statusText = match[2] || '';
            }
          }

          // Parse headers
          for (let i = 1; i < lines.length; i++) {
            const line = lines[i]!;
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
              const key = line.substring(0, colonIdx).trim().toLowerCase();
              const value = line.substring(colonIdx + 1).trim();
              headers.set(key, value);
            }
          }

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
          // Simple chunked decoding - look for final chunk
          const bodyStr = bodyData.toString('utf-8');
          if (bodyStr.includes('\r\n0\r\n')) {
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
 * Decode chunked transfer encoding.
 */
function decodeChunked(data: Buffer): string {
  let result = '';
  let offset = 0;
  const str = data.toString('utf-8');

  while (offset < str.length) {
    const lineEnd = str.indexOf('\r\n', offset);
    if (lineEnd === -1) break;

    const sizeLine = str.substring(offset, lineEnd);
    const size = parseInt(sizeLine, 16);
    if (isNaN(size) || size === 0) break;

    offset = lineEnd + 2;
    result += str.substring(offset, offset + size);
    offset += size + 2; // Skip chunk data and trailing \r\n
  }

  return result;
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
