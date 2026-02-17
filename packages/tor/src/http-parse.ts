/**
 * Shared HTTP/1.x response parsing utilities.
 *
 * Used by both the DirectoryClient (for directory stream responses)
 * and the browser http-fetch module (for web content fetching).
 */

export type ParsedHttpResponse = {
  statusCode: number;
  statusText: string;
  headers: Map<string, string>;
  body: string;
};

/**
 * Parse HTTP headers from a header section string.
 * Returns a Map with lowercase header names as keys.
 */
export function parseHttpHeaders(headerSection: string): Map<string, string> {
  const headers = new Map<string, string>();
  const lines = headerSection.split('\r\n');

  // Skip status line (first line), parse header lines
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const value = line.substring(colonIdx + 1).trim();
      headers.set(key, value);
    }
  }

  return headers;
}

/**
 * Parse an HTTP status line.
 * Returns the status code and status text, or null if malformed.
 */
export function parseHttpStatusLine(
  statusLine: string
): { statusCode: number; statusText: string } | null {
  const match = statusLine.match(/^HTTP\/\d+\.\d+\s+(\d+)\s*(.*)/);
  if (!match) {
    return null;
  }
  return {
    statusCode: parseInt(match[1]!, 10),
    statusText: match[2] ?? '',
  };
}

/**
 * Parse a complete HTTP response from a raw string.
 * Expects headers and body to be separated by \r\n\r\n.
 */
export function parseHttpResponse(raw: string): ParsedHttpResponse {
  const headerEnd = raw.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    throw new Error('Malformed HTTP response: missing header/body separator');
  }

  const headerSection = raw.slice(0, headerEnd);
  const body = raw.slice(headerEnd + 4);

  const lines = headerSection.split('\r\n');
  const statusLine = lines[0];
  if (!statusLine) {
    throw new Error('Malformed HTTP response: missing status line');
  }

  const status = parseHttpStatusLine(statusLine);
  if (!status) {
    throw new Error(`Malformed HTTP status line: ${statusLine}`);
  }

  const headers = parseHttpHeaders(headerSection);

  return {
    statusCode: status.statusCode,
    statusText: status.statusText,
    headers,
    body,
  };
}

/**
 * Decode HTTP chunked transfer encoding.
 *
 * Chunked format:
 *   <size-in-hex>\r\n
 *   <chunk-data>\r\n
 *   ...
 *   0\r\n
 *   \r\n
 *
 * Note: This returns a string (UTF-8 decoded). For binary data,
 * use decodeChunkedToBuffer instead.
 */
export function decodeChunked(data: string | Buffer): string {
  const str = typeof data === 'string' ? data : data.toString('utf-8');
  let result = '';
  let offset = 0;

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
 * Check if the response body appears to be complete for chunked encoding.
 * Looks for the final "0\r\n" chunk marker (size 0 indicates end).
 * Handles both mid-stream (preceded by \r\n) and start-of-body cases.
 */
export function isChunkedComplete(bodyStr: string): boolean {
  // Check for final chunk: either starts with "0\r\n" or contains "\r\n0\r\n"
  return bodyStr.startsWith('0\r\n') || bodyStr.includes('\r\n0\r\n');
}

const CRLF = Buffer.from('\r\n', 'ascii');
const ZERO_CRLF_CRLF = Buffer.from('0\r\n\r\n', 'ascii'); // 0x30 0x0d 0x0a 0x0d 0x0a

/**
 * Decode HTTP chunked transfer encoding on raw bytes.
 * Use this for binary data; for text use decodeChunked instead.
 */
export function decodeChunkedToBuffer(buffer: Buffer): Buffer {
  const parts: Buffer[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    const lineEnd = buffer.indexOf(CRLF, offset);
    if (lineEnd === -1) break;

    const sizeLine = buffer.subarray(offset, lineEnd).toString('ascii');
    const size = parseInt(sizeLine.trim(), 16);
    if (isNaN(size) || size === 0) break;

    offset = lineEnd + 2;
    if (offset + size > buffer.length) break;
    parts.push(buffer.subarray(offset, offset + size));
    offset += size + 2; // Skip chunk data and trailing \r\n
  }

  return Buffer.concat(parts);
}

/**
 * Detect end of chunked body: encoding ends with "0\r\n\r\n".
 */
export function isChunkedCompleteBuffer(buffer: Buffer): boolean {
  if (buffer.length < 5) return false;
  return buffer.subarray(-5).equals(ZERO_CRLF_CRLF);
}
