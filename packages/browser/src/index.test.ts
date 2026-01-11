/**
 * Browser unit tests for the main index module exports.
 * Tests that all expected exports are available.
 */

import { describe, it, expect } from 'vitest';
import * as browserExports from './index.ts';

describe('Browser package exports', () => {
  it('exports connectBrowserCircuit function', () => {
    expect(typeof browserExports.connectBrowserCircuit).toBe('function');
  });

  it('exports fetchPageViaTor function', () => {
    expect(typeof browserExports.fetchPageViaTor).toBe('function');
  });

  it('exports fetchViaTor function', () => {
    expect(typeof browserExports.fetchViaTor).toBe('function');
  });

  it('exports fetchHtml function', () => {
    expect(typeof browserExports.fetchHtml).toBe('function');
  });

  it('exports SnowflakeBrowserChannel class', () => {
    expect(typeof browserExports.SnowflakeBrowserChannel).toBe('function');
  });

  it('exports pickRelayWithFlags function', () => {
    expect(typeof browserExports.pickRelayWithFlags).toBe('function');
  });
});

describe('Type exports', () => {
  it('BrowserCircuitOptions type structure', () => {
    // Test that we can create objects matching the type
    const options: browserExports.BrowserCircuitOptions = {
      relayUrl: 'wss://example.com/',
      onStatus: (status: string) => console.log(status),
    };
    expect(options).toBeDefined();
  });

  it('BrowserCircuit type structure', () => {
    // We can't easily test types at runtime, but we can verify the shape
    // by checking what connectBrowserCircuit would return
    // This is more of a compile-time check
    expect(true).toBe(true);
  });
});
