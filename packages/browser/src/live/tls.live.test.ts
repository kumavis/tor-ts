/**
 * Live browser test for TLS handshake using @reclaimprotocol/tls.
 * Tests TLS 1.3 connectivity to Snowflake/Tor relay.
 *
 * This test validates that the reclaim TLS implementation properly
 * establishes TLS 1.3 connections, which is required by modern Tor relays.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { SnowflakeWsStack } from 'snowflake';
import { SmuxStreamDuplex } from '../shims/smux-duplex.ts';
import { connect as tlsConnect, TLSSocket } from '../shims/tls.ts';

/**
 * Generate a random server name for TLS SNI.
 */
function makeRandomServerName(): string {
  const array = new Uint8Array(Math.floor(Math.random() * 20 + 4));
  crypto.getRandomValues(array);
  const hex = Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `www.${hex}.net`;
}

describe('Reclaim TLS: Live Handshake', () => {
  let stack: SnowflakeWsStack | null = null;
  let tlsSocket: TLSSocket | null = null;

  afterEach(async () => {
    if (tlsSocket) {
      tlsSocket.destroy();
      tlsSocket = null;
    }
    if (stack) {
      await stack.close();
      stack = null;
    }
  });

  it('connects to Snowflake and completes TLS 1.3 handshake', async () => {
    console.log('[reclaim-tls-test] Connecting to Snowflake WebSocket...');

    stack = new SnowflakeWsStack({ relayUrl: 'wss://snowflake.torproject.net/' });
    await stack.connect();
    console.log('[reclaim-tls-test] WebSocket connected');

    console.log('[reclaim-tls-test] Opening SMUX stream...');
    const smuxStream = await stack.openStream();
    const streamDuplex = new SmuxStreamDuplex(smuxStream);
    console.log('[reclaim-tls-test] SMUX stream opened');

    console.log('[reclaim-tls-test] Starting TLS 1.3 handshake...');
    const serverName = makeRandomServerName();
    console.log('[reclaim-tls-test] Using SNI:', serverName);

    const handshakePromise = new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('TLS handshake timeout (30s)'));
      }, 30_000);

      tlsSocket = tlsConnect({
        socket: streamDuplex,
        servername: serverName,
        rejectUnauthorized: false,
      });

      tlsSocket.once('secureConnect', () => {
        clearTimeout(timeout);
        console.log('[reclaim-tls-test] TLS 1.3 handshake completed successfully!');
        resolve();
      });

      tlsSocket.once('error', (err: Error) => {
        clearTimeout(timeout);
        console.error('[reclaim-tls-test] TLS error:', err.message);
        reject(err);
      });
    });

    await handshakePromise;

    // Verify we got a peer certificate with raw DER data
    const cert = tlsSocket!.getPeerCertificate(true);
    console.log('[reclaim-tls-test] Peer certificate subject:', cert.subject);
    console.log('[reclaim-tls-test] Raw cert length:', cert.raw?.length);
    expect(cert.raw).toBeDefined();
    expect(cert.raw.length).toBeGreaterThan(0);
  }, 60_000);
});
