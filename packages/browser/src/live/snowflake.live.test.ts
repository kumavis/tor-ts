/**
 * Live browser tests for Snowflake connectivity.
 * These tests connect to the real Tor network via Snowflake.
 *
 * IMPORTANT: These tests require:
 * - Network access
 * - Access to snowflake.torproject.net
 * - Access to onionoo.torproject.org
 * - May take 60-180 seconds to complete
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { connectBrowserCircuit, fetchHtml } from '../index.ts';
import type { BrowserCircuit } from '../index.ts';

describe('Snowflake Live: Circuit Connection', () => {
  let circuit: BrowserCircuit | null = null;

  afterAll(() => {
    if (circuit) {
      circuit.destroy();
      circuit = null;
    }
  });

  it('connects to Tor via Snowflake', async () => {
    const statusMessages: string[] = [];

    circuit = await connectBrowserCircuit({
      onStatus: (status) => {
        console.log('[test] Status:', status);
        statusMessages.push(status);
      },
    });

    expect(circuit).toBeDefined();
    expect(circuit.circuit).toBeDefined();
    expect(circuit.channel).toBeDefined();
    expect(typeof circuit.destroy).toBe('function');

    // Verify we received status updates
    expect(statusMessages.length).toBeGreaterThan(0);
    expect(statusMessages.some((s) => s.includes('directory') || s.includes('Directory'))).toBe(
      true
    );
  }, 180_000); // 3 minute timeout
});

describe('Snowflake Live: Fetch via Tor', () => {
  let circuit: BrowserCircuit | null = null;

  beforeAll(async () => {
    console.log('[test] Connecting to Tor via Snowflake...');
    circuit = await connectBrowserCircuit({
      onStatus: (status) => {
        console.log('[test] Status:', status);
      },
    });
    console.log('[test] Connected!');
  }, 180_000);

  afterAll(() => {
    if (circuit) {
      circuit.destroy();
      circuit = null;
    }
  });

  it('fetches example.com HTML through Tor', async () => {
    expect(circuit).toBeDefined();

    console.log('[test] Fetching https://example.com/...');
    const html = await fetchHtml(circuit!.circuit, 'https://example.com/');

    expect(html).toBeDefined();
    expect(typeof html).toBe('string');
    expect(html.length).toBeGreaterThan(100);
    expect(html).toContain('Example Domain');
    console.log('[test] Received', html.length, 'bytes');
  }, 60_000); // 1 minute timeout for fetch

  it('fetches httpbin.org/ip to verify exit node', async () => {
    expect(circuit).toBeDefined();

    console.log('[test] Fetching https://httpbin.org/ip...');
    const response = await fetchHtml(circuit!.circuit, 'https://httpbin.org/ip');

    expect(response).toBeDefined();
    expect(typeof response).toBe('string');
    // Response should be JSON with "origin" field containing an IP
    expect(response).toContain('origin');
    console.log('[test] Response:', response);
  }, 60_000);
});

describe('Snowflake Live: Error Handling', () => {
  let circuit: BrowserCircuit | null = null;

  beforeAll(async () => {
    circuit = await connectBrowserCircuit({
      onStatus: (status) => console.log('[test] Status:', status),
    });
  }, 180_000);

  afterAll(() => {
    if (circuit) {
      circuit.destroy();
      circuit = null;
    }
  });

  it('handles fetch to non-existent domain', async () => {
    expect(circuit).toBeDefined();

    await expect(
      fetchHtml(circuit!.circuit, 'https://this-domain-definitely-does-not-exist-12345.com/')
    ).rejects.toThrow();
  }, 60_000);

  it('handles fetch with invalid URL', async () => {
    expect(circuit).toBeDefined();

    await expect(fetchHtml(circuit!.circuit, 'not-a-valid-url')).rejects.toThrow();
  }, 10_000);
});
