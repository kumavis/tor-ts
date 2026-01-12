/**
 * Live browser tests for Snowflake connectivity.
 * These tests connect to the real Tor network via Snowflake.
 *
 * IMPORTANT: These tests require:
 * - Network access
 * - Access to snowflake.torproject.net
 * - May take 60-180 seconds to complete
 *
 * The circuit is established ONCE at the start and shared across all tests
 * to avoid repeatedly downloading the ~3.35MB consensus.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { connectBrowserCircuit, fetchHtml } from '../index.ts';
import type { BrowserCircuit } from '../index.ts';

// Shared circuit - established once, used by all tests
let sharedCircuit: BrowserCircuit | null = null;
const statusMessages: string[] = [];

/**
 * Global setup - connect to Tor once before all tests.
 * This downloads the consensus (~3.35MB) which is slow in browser JS TLS.
 */
beforeAll(async () => {
  console.log('[test] Establishing shared Tor circuit via Snowflake...');
  console.log('[test] This downloads ~3.35MB consensus - please be patient...');

  sharedCircuit = await connectBrowserCircuit({
    onStatus: (status) => {
      console.log('[test] Status:', status);
      statusMessages.push(status);
    },
    onConsensusProgress: (progress) => {
      // Log progress every 500KB
      if (progress.bytesReceived % 500_000 < 10_000) {
        console.log(
          `[test] Consensus download: ${(progress.bytesReceived / 1024 / 1024).toFixed(2)} MB`
        );
      }
    },
    // Browser signature verification not yet implemented
    // (Web Crypto API doesn't support Tor's unprefixed PKCS#1 v1.5 signatures)
    dangerouslySkipSignatureVerification: true,
  });

  console.log('[test] Shared circuit established!');
}, 600_000); // 10 minute timeout - consensus download via JS TLS is slow

/**
 * Global teardown - destroy the circuit after all tests.
 */
afterAll(() => {
  if (sharedCircuit) {
    console.log('[test] Destroying shared circuit...');
    sharedCircuit.destroy();
    sharedCircuit = null;
  }
});

describe('Snowflake Live: Circuit Connection', () => {
  it('establishes a valid circuit', () => {
    expect(sharedCircuit).toBeDefined();
    expect(sharedCircuit!.circuit).toBeDefined();
    expect(sharedCircuit!.channel).toBeDefined();
    expect(typeof sharedCircuit!.destroy).toBe('function');
  }, 180_000);

  it('received status updates during connection', () => {
    expect(statusMessages.length).toBeGreaterThan(0);
    // Check for bootstrap-related keywords in status messages
    expect(
      statusMessages.some(
        (s) =>
          s.includes('consensus') ||
          s.includes('Snowflake') ||
          s.includes('bootstrap') ||
          s.includes('circuit')
      )
    ).toBe(true);
  }, 180_000);

  it('received circuit established message', () => {
    expect(statusMessages.some((s) => s.includes('established') || s.includes('Circuit'))).toBe(
      true
    );
  }, 180_000);
});

describe('Snowflake Live: Fetch via Tor', () => {
  it('fetches example.com HTML through Tor', async () => {
    expect(sharedCircuit).toBeDefined();

    console.log('[test] Fetching https://example.com/...');
    const html = await fetchHtml(sharedCircuit!.circuit, 'https://example.com/');

    expect(html).toBeDefined();
    expect(typeof html).toBe('string');
    expect(html.length).toBeGreaterThan(100);
    expect(html).toContain('Example Domain');
    console.log('[test] Received', html.length, 'bytes');
  }, 180_000);

  it('fetches httpbin.org/ip to verify exit node', async () => {
    expect(sharedCircuit).toBeDefined();

    console.log('[test] Fetching https://httpbin.org/ip...');
    const response = await fetchHtml(sharedCircuit!.circuit, 'https://httpbin.org/ip');

    expect(response).toBeDefined();
    expect(typeof response).toBe('string');
    // Response should be JSON with "origin" field containing an IP
    expect(response).toContain('origin');
    console.log('[test] Response:', response);
  }, 180_000);
});

describe('Snowflake Live: Error Handling', () => {
  it('handles fetch to non-existent domain', async () => {
    expect(sharedCircuit).toBeDefined();

    await expect(
      fetchHtml(sharedCircuit!.circuit, 'https://this-domain-definitely-does-not-exist-12345.com/')
    ).rejects.toThrow();
  }, 180_000);

  it('handles fetch with invalid URL', async () => {
    expect(sharedCircuit).toBeDefined();

    await expect(fetchHtml(sharedCircuit!.circuit, 'not-a-valid-url')).rejects.toThrow();
  }, 180_000);
});

// Note: Consensus Signature Verification tests are in a separate file
// (consensus-signature-crypto.spec.ts) and run in Node.js where the
// crypto implementation is complete. Browser signature verification
// is not yet implemented because Web Crypto API only supports standard
// RSASSA-PKCS1-v1_5 with DigestInfo, but Tor uses unprefixed PKCS#1 v1.5.
