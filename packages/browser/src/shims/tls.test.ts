/**
 * Browser unit tests for the TLS shim.
 * Tests that node-forge based TLS implementation exports correct interface.
 */

import { describe, it, expect } from 'vitest';
import { connect, TLSSocket } from './tls.ts';
import forge from 'node-forge';

describe('TLSSocket', () => {
  it('exports TLSSocket class', () => {
    expect(typeof TLSSocket).toBe('function');
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
      // @ts-expect-error - Testing runtime error for unsupported overload
      connect(443, 'example.com', {});
    }).toThrow('not supported in browser');
  });
});

describe('node-forge availability', () => {
  it('forge is available', () => {
    expect(forge).toBeDefined();
  });

  it('forge.tls is available', () => {
    expect(forge.tls).toBeDefined();
    expect(typeof forge.tls.createConnection).toBe('function');
  });

  it('forge.pki is available for certificate handling', () => {
    expect(forge.pki).toBeDefined();
    expect(typeof forge.pki.certificateToAsn1).toBe('function');
  });

  it('forge.asn1 is available', () => {
    expect(forge.asn1).toBeDefined();
    expect(typeof forge.asn1.toDer).toBe('function');
  });

  it('forge.util is available', () => {
    expect(forge.util).toBeDefined();
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
    expect(buf.every(b => b === 0)).toBe(true);
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
});
