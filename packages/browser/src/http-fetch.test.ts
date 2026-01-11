/**
 * Browser unit tests for HTTP fetch utilities.
 * These test the shared HTTP parsing logic from tor/http-parse in a real browser environment.
 */

import { describe, it, expect } from 'vitest';
import {
  decodeChunked,
  parseHttpHeaders,
  parseHttpStatusLine,
  isChunkedComplete,
  parseHttpResponse,
} from 'tor/http-parse';

describe('decodeChunked', () => {
  it('handles single chunk', () => {
    const result = decodeChunked('5\r\nhello\r\n0\r\n\r\n');
    expect(result).toBe('hello');
  });

  it('handles multiple chunks', () => {
    const result = decodeChunked('5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n');
    expect(result).toBe('hello world');
  });

  it('handles empty response', () => {
    const result = decodeChunked('0\r\n\r\n');
    expect(result).toBe('');
  });

  it('handles large hex sizes (0x1a = 26 bytes)', () => {
    const content = 'abcdefghijklmnopqrstuvwxyz';
    const result = decodeChunked(`1a\r\n${content}\r\n0\r\n\r\n`);
    expect(result).toBe(content);
  });

  it('handles uppercase hex sizes', () => {
    const content = 'abcdefghijklmnopqrstuvwxyz';
    const result = decodeChunked(`1A\r\n${content}\r\n0\r\n\r\n`);
    expect(result).toBe(content);
  });

  it('handles content with special characters', () => {
    const content = 'test<>data';
    const result = decodeChunked(`a\r\n${content}\r\n0\r\n\r\n`);
    expect(result).toBe(content);
  });

  it('handles Buffer input', () => {
    const buffer = Buffer.from('5\r\nhello\r\n0\r\n\r\n', 'utf-8');
    const result = decodeChunked(buffer);
    expect(result).toBe('hello');
  });
});

describe('isChunkedComplete', () => {
  it('returns true when final chunk marker present', () => {
    expect(isChunkedComplete('5\r\nhello\r\n0\r\n\r\n')).toBe(true);
  });

  it('returns false when final chunk marker missing', () => {
    expect(isChunkedComplete('5\r\nhello\r\n')).toBe(false);
  });

  it('returns true for empty chunked response', () => {
    expect(isChunkedComplete('0\r\n\r\n')).toBe(true);
  });
});

describe('parseHttpStatusLine', () => {
  it('parses HTTP/1.1 200 OK', () => {
    const result = parseHttpStatusLine('HTTP/1.1 200 OK');
    expect(result).toEqual({ statusCode: 200, statusText: 'OK' });
  });

  it('parses HTTP/1.0 404 Not Found', () => {
    const result = parseHttpStatusLine('HTTP/1.0 404 Not Found');
    expect(result).toEqual({ statusCode: 404, statusText: 'Not Found' });
  });

  it('parses HTTP/1.1 500 Internal Server Error', () => {
    const result = parseHttpStatusLine('HTTP/1.1 500 Internal Server Error');
    expect(result).toEqual({ statusCode: 500, statusText: 'Internal Server Error' });
  });

  it('handles status with no text', () => {
    const result = parseHttpStatusLine('HTTP/1.1 204');
    expect(result).toEqual({ statusCode: 204, statusText: '' });
  });

  it('returns null for malformed status line', () => {
    expect(parseHttpStatusLine('not a status line')).toBeNull();
    expect(parseHttpStatusLine('')).toBeNull();
  });
});

describe('parseHttpHeaders', () => {
  it('extracts content-length header', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nContent-Type: text/html';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('content-length')).toBe('1234');
  });

  it('extracts content-type header', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('application/json; charset=utf-8');
  });

  it('handles headers with colons in value', () => {
    const headerSection = 'HTTP/1.1 301 Moved\r\nLocation: https://example.com:8080/path';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('location')).toBe('https://example.com:8080/path');
  });

  it('detects chunked transfer encoding', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('transfer-encoding')).toBe('chunked');
  });

  it('normalizes header names to lowercase', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nCONTENT-TYPE: text/html\r\nX-Custom-Header: value';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('text/html');
    expect(headers.get('x-custom-header')).toBe('value');
  });

  it('trims whitespace from header values', () => {
    const headerSection = 'HTTP/1.1 200 OK\r\nContent-Type:   text/html  ';
    const headers = parseHttpHeaders(headerSection);
    expect(headers.get('content-type')).toBe('text/html');
  });
});

describe('parseHttpResponse', () => {
  it('parses complete HTTP response', () => {
    const raw = 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello';
    const result = parseHttpResponse(raw);
    expect(result.statusCode).toBe(200);
    expect(result.statusText).toBe('OK');
    expect(result.headers.get('content-length')).toBe('5');
    expect(result.body).toBe('hello');
  });

  it('throws on missing header separator', () => {
    expect(() => parseHttpResponse('HTTP/1.1 200 OK')).toThrow('missing header/body separator');
  });

  it('throws on missing status line', () => {
    expect(() => parseHttpResponse('\r\n\r\n')).toThrow('missing status line');
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
