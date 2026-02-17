/**
 * Live browser tests for Snowflake connectivity.
 * These tests connect to the real Tor network via Snowflake.
 *
 * IMPORTANT: These tests require:
 * - Network access
 * - Access to snowflake.torproject.net
 * - May take 60-180 seconds to complete
 *
 * The client is established ONCE at the start and shared across all tests
 * to avoid repeatedly downloading the ~3.35MB consensus.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { makeBrowserTorClient, fetchHtml } from '../index.ts';
import type { BrowserTorClient } from '../index.ts';

// Shared client - established once, used by all tests
let sharedClient: BrowserTorClient | null = null;
const statusMessages: string[] = [];

/**
 * Global setup - connect to Tor once before all tests.
 * This downloads the consensus (~3.35MB) which is slow in browser JS TLS.
 */
beforeAll(async () => {
  console.log('[test] Establishing shared Tor client via Snowflake...');
  console.log('[test] This downloads ~3.35MB consensus - please be patient...');

  const result = await makeBrowserTorClient({
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
    // Signature verification is enabled - uses pure-JS RSA for Tor's unprefixed PKCS#1 v1.5 signatures
  });

  sharedClient = result.client;
  console.log('[test] Shared client established!');
}, 600_000); // 10 minute timeout - consensus download via JS TLS is slow

/**
 * Global teardown - destroy the client after all tests.
 */
afterAll(() => {
  if (sharedClient) {
    console.log('[test] Destroying shared client...');
    sharedClient.destroy();
    sharedClient = null;
  }
});

describe('Snowflake Live: Client Connection', () => {
  it('establishes a valid client', () => {
    expect(sharedClient).toBeDefined();
    expect(sharedClient!.consensus).toBeDefined();
    expect(typeof sharedClient!.fetch).toBe('function');
    expect(typeof sharedClient!.destroy).toBe('function');
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

  it('received client established message', () => {
    expect(
      statusMessages.some(
        (s) => s.includes('established') || s.includes('Client') || s.includes('initialized')
      )
    ).toBe(true);
  }, 180_000);
});

describe('Snowflake Live: Fetch via Tor', () => {
  it('fetches example.com HTML through Tor', async () => {
    expect(sharedClient).toBeDefined();

    console.log('[test] Fetching https://example.com/...');
    const html = await fetchHtml(sharedClient!, 'https://example.com/');

    expect(html).toBeDefined();
    expect(typeof html).toBe('string');
    expect(html.length).toBeGreaterThan(100);
    expect(html).toContain('Example Domain');
    console.log('[test] Received', html.length, 'bytes');
  }, 180_000);

  it('fetches httpbin.org/ip to verify exit node', async () => {
    expect(sharedClient).toBeDefined();

    console.log('[test] Fetching https://httpbin.org/ip...');
    const response = await sharedClient!.fetch('https://httpbin.org/ip');

    expect(response).toBeDefined();
    expect(response.status).toBe(200);
    // Response should be JSON with "origin" field containing an IP
    const body = new TextDecoder().decode(response.body);
    expect(body).toContain('origin');
    console.log('[test] Response:', body);
  }, 180_000);
});

describe('Snowflake Live: Error Handling', () => {
  it('handles fetch to non-existent domain', async () => {
    expect(sharedClient).toBeDefined();

    await expect(
      sharedClient!.fetch('https://this-domain-definitely-does-not-exist-12345.com/')
    ).rejects.toThrow();
  }, 180_000);

  it('handles fetch with invalid URL', async () => {
    expect(sharedClient).toBeDefined();

    await expect(sharedClient!.fetch('not-a-valid-url')).rejects.toThrow();
  }, 180_000);
});

// Note: Consensus Signature Verification uses pure-JS RSA (BigInt modular exponentiation)
// to verify Tor's unprefixed PKCS#1 v1.5 signatures. Web Crypto API only supports standard
// RSASSA-PKCS1-v1_5 with DigestInfo, but Tor uses unprefixed PKCS#1 v1.5, so we implement
// the verification using raw RSA operations in the browser shim (crypto-webcrypto.ts).
// Additional tests for the signature verification are in consensus-signature-crypto.spec.ts.
