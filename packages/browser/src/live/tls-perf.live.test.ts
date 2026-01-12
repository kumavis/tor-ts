/**
 * TLS Performance Benchmark: SubtleCrypto vs Pure JS
 *
 * This test measures actual TLS handshake and data transfer performance
 * by connecting to a real Tor relay via Snowflake.
 *
 * Since setCryptoImplementation is global, we run separate tests and
 * compare the timings manually.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { SnowflakeWsStack } from 'snowflake';
import { SmuxStreamDuplex } from '../shims/smux-duplex.ts';
import { setCryptoImplementation } from '@reclaimprotocol/tls';
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto';
import { pureJsCrypto } from '@reclaimprotocol/tls/purejs-crypto';
import { connect as tlsConnect, TLSSocket } from '../shims/tls.ts';

function makeRandomServerName(): string {
  const array = new Uint8Array(Math.floor(Math.random() * 20 + 4));
  crypto.getRandomValues(array);
  const hex = Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `www.${hex}.net`;
}

interface TlsTimings {
  connectMs: number;
  handshakeMs: number;
}

async function measureTlsPerformance(cryptoName: string): Promise<TlsTimings> {
  const connectStart = performance.now();

  // Connect to Snowflake
  const stack = new SnowflakeWsStack({ relayUrl: 'wss://snowflake.torproject.net/' });
  await stack.connect();

  const smuxStream = await stack.openStream();
  const streamDuplex = new SmuxStreamDuplex(smuxStream);

  const connectMs = performance.now() - connectStart;
  console.log(`[${cryptoName}] Snowflake connect: ${connectMs.toFixed(2)}ms`);

  // Measure TLS handshake
  const handshakeStart = performance.now();

  const tlsSocket = await new Promise<TLSSocket>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('TLS timeout')), 30000);

    const socket = tlsConnect({
      socket: streamDuplex,
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
    });

    socket.once('secureConnect', () => {
      clearTimeout(timeout);
      resolve(socket);
    });

    socket.once('error', (err: Error) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  const handshakeMs = performance.now() - handshakeStart;
  console.log(`[${cryptoName}] TLS handshake: ${handshakeMs.toFixed(2)}ms`);

  // Cleanup
  tlsSocket.destroy();
  await stack.close();

  return { connectMs, handshakeMs };
}

// Store results for comparison
const results: Record<string, TlsTimings> = {};

describe('TLS Performance Comparison', () => {
  afterEach(() => {
    // Print comparison if we have both results
    if (results['SubtleCrypto'] && results['PureJS']) {
      const subtle = results['SubtleCrypto']!;
      const pureJs = results['PureJS']!;

      console.log('\n========================================');
      console.log('=== TLS PERFORMANCE COMPARISON ===');
      console.log('========================================');
      console.log(`SubtleCrypto handshake: ${subtle.handshakeMs.toFixed(2)}ms`);
      console.log(`Pure JS handshake:      ${pureJs.handshakeMs.toFixed(2)}ms`);

      const speedup = pureJs.handshakeMs / subtle.handshakeMs;
      if (speedup > 1) {
        console.log(`\n>>> SubtleCrypto is ${speedup.toFixed(2)}x FASTER <<<`);
      } else {
        console.log(`\n>>> Pure JS is ${(1 / speedup).toFixed(2)}x FASTER <<<`);
      }
      console.log('========================================\n');
    }
  });

  it('measures TLS handshake with SubtleCrypto (webcryptoCrypto)', async () => {
    console.log('\n=== Testing SubtleCrypto ===');
    setCryptoImplementation(webcryptoCrypto);

    const timings = await measureTlsPerformance('SubtleCrypto');
    results['SubtleCrypto'] = timings;

    expect(timings.handshakeMs).toBeGreaterThan(0);
  }, 60000);

  it('measures TLS handshake with Pure JS (pureJsCrypto)', async () => {
    console.log('\n=== Testing Pure JS ===');
    setCryptoImplementation(pureJsCrypto);

    const timings = await measureTlsPerformance('PureJS');
    results['PureJS'] = timings;

    expect(timings.handshakeMs).toBeGreaterThan(0);
  }, 60000);
});
