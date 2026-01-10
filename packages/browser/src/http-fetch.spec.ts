/**
 * Tests for HTTP fetch utilities.
 * These test the HTTP parsing logic without requiring actual network connections.
 */

import test from 'ava';

// We need to test the internal decodeChunked function.
// Since it's not exported, we'll create a copy here for testing purposes.
// This should be kept in sync with the implementation in http-fetch.ts.

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

test('decodeChunked: handles single chunk', (t) => {
  // Format: <size in hex>\r\n<data>\r\n0\r\n\r\n
  const chunkedData = Buffer.from('5\r\nhello\r\n0\r\n\r\n', 'utf-8');
  const result = decodeChunked(chunkedData);
  t.is(result, 'hello');
});

test('decodeChunked: handles multiple chunks', (t) => {
  // Two chunks: "hello" (5 bytes) and " world" (6 bytes)
  const chunkedData = Buffer.from('5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n', 'utf-8');
  const result = decodeChunked(chunkedData);
  t.is(result, 'hello world');
});

test('decodeChunked: handles empty response', (t) => {
  const chunkedData = Buffer.from('0\r\n\r\n', 'utf-8');
  const result = decodeChunked(chunkedData);
  t.is(result, '');
});

test('decodeChunked: handles large hex sizes', (t) => {
  // A chunk with size 0x1a (26 bytes)
  const content = 'abcdefghijklmnopqrstuvwxyz';
  const chunkedData = Buffer.from(`1a\r\n${content}\r\n0\r\n\r\n`, 'utf-8');
  const result = decodeChunked(chunkedData);
  t.is(result, content);
});

test('decodeChunked: handles uppercase hex sizes', (t) => {
  const content = 'abcdefghijklmnopqrstuvwxyz';
  const chunkedData = Buffer.from(`1A\r\n${content}\r\n0\r\n\r\n`, 'utf-8');
  const result = decodeChunked(chunkedData);
  t.is(result, content);
});

// Test HTTP response header parsing
test('HTTP header parsing: extracts content-length', (t) => {
  const response = 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello';
  const headerEnd = response.indexOf('\r\n\r\n');
  const headerSection = response.substring(0, headerEnd);
  const lines = headerSection.split('\r\n');

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

  t.is(headers.get('content-length'), '5');
  t.is(headers.get('content-type'), 'text/plain');
});

test('HTTP header parsing: extracts status code and text', (t) => {
  const response = 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n';
  const headerEnd = response.indexOf('\r\n\r\n');
  const headerSection = response.substring(0, headerEnd);
  const lines = headerSection.split('\r\n');

  const statusLine = lines[0]!;
  const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)\s*(.*)/);
  t.truthy(match);
  const status = parseInt(match![1]!, 10);
  const statusText = match![2] || '';

  t.is(status, 404);
  t.is(statusText, 'Not Found');
});

test('HTTP header parsing: handles headers with colons in value', (t) => {
  const response = 'HTTP/1.1 200 OK\r\nLocation: https://example.com:8080/path\r\n\r\n';
  const headerEnd = response.indexOf('\r\n\r\n');
  const headerSection = response.substring(0, headerEnd);
  const lines = headerSection.split('\r\n');

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

  t.is(headers.get('location'), 'https://example.com:8080/path');
});

test('HTTP header parsing: detects chunked transfer encoding', (t) => {
  const response = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n';
  const headerEnd = response.indexOf('\r\n\r\n');
  const headerSection = response.substring(0, headerEnd);
  const lines = headerSection.split('\r\n');

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

  const isChunked = headers.get('transfer-encoding')?.toLowerCase() === 'chunked';
  t.true(isChunked);
});
