/**
 * Browser unit tests for the TLS shim.
 * Tests that @reclaimprotocol/tls based TLS implementation exports correct interface.
 */

import { describe, it, expect } from 'vitest';
import { connect, TLSSocket } from './tls.ts';

describe('TLSSocket', () => {
  it('exports TLSSocket class', () => {
    expect(typeof TLSSocket).toBe('function');
  });

  it('TLSSocket extends EventEmitter', () => {
    // TLSSocket should have EventEmitter methods
    expect(TLSSocket.prototype.on).toBeDefined();
    expect(TLSSocket.prototype.emit).toBeDefined();
    expect(TLSSocket.prototype.once).toBeDefined();
  });
});

describe('tls.connect', () => {
  it('exports connect function', () => {
    expect(typeof connect).toBe('function');
  });

  it('throws when called without socket option', () => {
    expect(() => {
      connect({});
    }).toThrow('socket option');
  });

  it('throws when called with port/host (unsupported in browser)', () => {
    expect(() => {
      connect(443, 'example.com', {});
    }).toThrow('not supported in browser');
  });
});

describe('Crypto polyfills', () => {
  it('Buffer is available (polyfilled)', () => {
    expect(typeof Buffer).toBe('function');
    const buf = Buffer.from('hello', 'utf-8');
    expect(buf.length).toBe(5);
    expect(buf.toString('utf-8')).toBe('hello');
  });

  it('Buffer.alloc works', () => {
    const buf = Buffer.alloc(10);
    expect(buf.length).toBe(10);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  it('Buffer.from with hex encoding', () => {
    const buf = Buffer.from('deadbeef', 'hex');
    expect(buf.length).toBe(4);
    expect(buf[0]).toBe(0xde);
    expect(buf[1]).toBe(0xad);
    expect(buf[2]).toBe(0xbe);
    expect(buf[3]).toBe(0xef);
  });

  it('Buffer.from with base64 encoding', () => {
    const buf = Buffer.from('aGVsbG8=', 'base64');
    expect(buf.toString('utf-8')).toBe('hello');
  });

  it('Buffer can be converted to Uint8Array', () => {
    const buf = Buffer.from([1, 2, 3, 4, 5]);
    expect(buf).toBeInstanceOf(Uint8Array);
    expect(buf[0]).toBe(1);
  });

  it('crypto.getRandomValues is available', () => {
    expect(typeof crypto.getRandomValues).toBe('function');
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    // Very unlikely to be all zeros
    expect(array.some((b) => b !== 0)).toBe(true);
  });
});
