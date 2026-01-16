/**
 * Browser unit tests for the main index module exports.
 * Tests that all expected exports are available.
 */

import { describe, it, expect } from 'vitest';
import * as browserExports from './index.ts';

describe('Browser package exports', () => {
  it('exports makeBrowserTorClient function', () => {
    expect(typeof browserExports.makeBrowserTorClient).toBe('function');
  });

  it('exports fetchHtml function', () => {
    expect(typeof browserExports.fetchHtml).toBe('function');
  });

  it('exports createSnowflakeChannelManager function', () => {
    expect(typeof browserExports.createSnowflakeChannelManager).toBe('function');
  });

  it('exports SnowflakeBrowserChannel class', () => {
    expect(typeof browserExports.SnowflakeBrowserChannel).toBe('function');
  });

  it('exports TorClient class', () => {
    expect(typeof browserExports.TorClient).toBe('function');
  });

  it('exports isOnionAddress function', () => {
    expect(typeof browserExports.isOnionAddress).toBe('function');
  });

  it('exports consensus cache utilities', () => {
    expect(typeof browserExports.clearCachedConsensus).toBe('function');
    expect(typeof browserExports.hasCachedConsensus).toBe('function');
    expect(typeof browserExports.getConsensusCacheStatus).toBe('function');
  });
});

describe('Type exports', () => {
  it('BrowserTorClientOptions type structure', () => {
    // Test that we can create objects matching the type
    const options: browserExports.BrowserTorClientOptions = {
      relayUrl: 'wss://example.com/',
      onStatus: (status: string) => console.log(status),
    };
    expect(options).toBeDefined();
  });

  it('FetchOptions type structure', () => {
    const options: browserExports.FetchOptions = {
      method: 'GET',
      headers: { Accept: 'text/html' },
      timeout: 30000,
    };
    expect(options).toBeDefined();
  });
});
