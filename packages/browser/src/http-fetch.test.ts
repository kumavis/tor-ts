/**
 * Browser unit tests for HTTP fetch utilities.
 * These test the HTTP parsing logic in a real browser environment.
 */

import { describe, it, expect } from 'vitest';

/**
 * Decode chunked transfer encoding.
 * This is a copy of the internal function from http-fetch.ts for testing.
 */
function decodeChunked(data: Uint8Array): string {
  let result = '';
  let offset = 0;
  const str = new TextDecoder().decode(data);

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
 * Parse HTTP response headers.
 */
function parseHttpHeaders(headerSection: string): {
  status: number;
  statusText: string;
  headers: Map<string, string>;
} {
  const lines = headerSection.split('\r\n');
  const statusLine = lines[0] || '';
  const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)/);

  const status = match ? parseInt(match[1]!, 10) : 0;
  const statusText = match?.[2] || '';

  const headers = new Map<string, string>();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const value = line.substring(colonIdx + 1).trim();
      headers.set(key, value);
    }
  }

  return { status, statusText, headers };
}

describe('decodeChunked', () => {
  it('handles single chunk', () => {
    const chunkedData = new TextEncoder().encode('5\r\nhello\r\n0\r\n\r\n');
    const result = decodeChunked(chunkedData);
    expect(result).toBe('hello');
  });

  it('handles multiple chunks', () => {
    const chunkedData = new TextEncoder().encode('5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n');
    const result = decodeChunked(chunkedData);
    expect(result).toBe('hello world');
  });

  it('handles empty response', () => {
    const chunkedData = new TextEncoder().encode('0\r\n\r\n');
    const result = decodeChunked(chunkedData);
    expect(result).toBe('');
  });

  it('handles large hex sizes (0x1a = 26 bytes)', () => {
    const content = 'abcdefghijklmnopqrstuvwxyz';
    const chunkedData = new TextEncoder().encode(`1a\r\n${content}\r\n0\r\n\r\n`);
    const result = decodeChunked(chunkedData);
    expect(result).toBe(content);
  });

  it('handles uppercase hex sizes', () => {
    const content = 'abcdefghijklmnopqrstuvwxyz';
    const chunkedData = new TextEncoder().encode(`1A\r\n${content}\r\n0\r\n\r\n`);
    const result = decodeChunked(chunkedData);
    expect(result).toBe(content);
  });

  it('handles content with special characters', () => {
    // Content with special chars that are valid UTF-8
    const content = 'test<>data';
    const chunkedData = new TextEncoder().encode(`a\r\n${content}\r\n0\r\n\r\n`);
    const result = decodeChunked(chunkedData);
    expect(result).toBe(content);
  });
});

describe('parseHttpHeaders', () => {
  it('extracts status code and text', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Length: 5';
    const { status, statusText } = parseHttpHeaders(headerSection);
    expect(status).toBe(200);
    expect(statusText).toBe('OK');
  });

  it('handles 404 Not Found', () => {
    const headerSection = 'HTTP/1.1 404 Not Found\r\nContent-Length: 0';
    const { status, statusText } = parseHttpHeaders(headerSection);
    expect(status).toBe(404);
    expect(statusText).toBe('Not Found');
  });

  it('handles 500 Internal Server Error', () => {
    const headerSection = 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0';
    const { status, statusText } = parseHttpHeaders(headerSection);
    expect(status).toBe(500);
    expect(statusText).toBe('Internal Server Error');
  });

  it('extracts content-length header', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nContent-Type: text/html';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('content-length')).toBe('1234');
  });

  it('extracts content-type header', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('application/json; charset=utf-8');
  });

  it('handles headers with colons in value', () => {
    const headerSection = 'HTTP/1.1 301 Moved\r\nLocation: https://example.com:8080/path';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('location')).toBe('https://example.com:8080/path');
  });

  it('detects chunked transfer encoding', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('transfer-encoding')).toBe('chunked');
  });

  it('normalizes header names to lowercase', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nCONTENT-TYPE: text/html\r\nX-Custom-Header: value';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('text/html');
    expect(headers.get('x-custom-header')).toBe('value');
  });

  it('trims whitespace from header values', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Type:   text/html  ';
    const { headers } = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('text/html');
  });
});

describe('Browser APIs', () => {
  it('TextEncoder is available', () => {
    expect(typeof TextEncoder).toBe('function');
    const encoder = new TextEncoder();
    const data = encoder.encode('hello');
    expect(data).toBeInstanceOf(Uint8Array);
    expect(data.length).toBe(5);
  });

  it('TextDecoder is available', () => {
    expect(typeof TextDecoder).toBe('function');
    const decoder = new TextDecoder();
    const data = new Uint8Array([104, 101, 108, 108, 111]);
    expect(decoder.decode(data)).toBe('hello');
  });

  it('crypto.getRandomValues is available', () => {
    expect(typeof crypto.getRandomValues).toBe('function');
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    // At least some bytes should be non-zero
    expect(array.some((b) => b !== 0)).toBe(true);
  });

  it('fetch is available', () => {
    expect(typeof fetch).toBe('function');
  });

  it('WebSocket is available', () => {
    expect(typeof WebSocket).toBe('function');
  });

  it('Map is available with expected methods', () => {
    const map = new Map<string, string>();
    map.set('key', 'value');
    expect(map.get('key')).toBe('value');
    expect(map.has('key')).toBe(true);
  });
});
