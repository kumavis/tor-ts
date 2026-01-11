/**
 * Browser unit tests for the WebSocket shim.
 * Tests that the shim correctly wraps native WebSocket with EventEmitter interface.
 */

import { describe, it, expect } from 'vitest';
import WebSocketShim from './ws.ts';

describe('WebSocketShim', () => {
  it('exports WebSocket class', () => {
    expect(typeof WebSocketShim).toBe('function');
  });

  it('has static state constants matching native WebSocket', () => {
    expect(WebSocketShim.CONNECTING).toBe(0);
    expect(WebSocketShim.OPEN).toBe(1);
    expect(WebSocketShim.CLOSING).toBe(2);
    expect(WebSocketShim.CLOSED).toBe(3);
  });

  it('constants match native WebSocket values', () => {
    expect(WebSocketShim.CONNECTING).toBe(WebSocket.CONNECTING);
    expect(WebSocketShim.OPEN).toBe(WebSocket.OPEN);
    expect(WebSocketShim.CLOSING).toBe(WebSocket.CLOSING);
    expect(WebSocketShim.CLOSED).toBe(WebSocket.CLOSED);
  });

  it('can be instantiated with a URL', () => {
    // We can't actually connect without a server, but we can test instantiation
    // This will immediately try to connect and fail, but the object should exist
    expect(() => {
      const ws = new WebSocketShim('wss://localhost:9999/test');
      // Suppress expected error events
      ws.on('error', () => {});
      // Clean up
      ws.close();
    }).not.toThrow();
  });

  it('inherits from EventEmitter (has on/emit methods)', () => {
    const ws = new WebSocketShim('wss://localhost:9999/test');
    ws.on('error', () => {}); // Suppress expected errors
    expect(typeof ws.on).toBe('function');
    expect(typeof ws.emit).toBe('function');
    expect(typeof ws.once).toBe('function');
    expect(typeof ws.removeListener).toBe('function');
    ws.close();
  });

  it('has send method', () => {
    const ws = new WebSocketShim('wss://localhost:9999/test');
    ws.on('error', () => {}); // Suppress expected errors
    expect(typeof ws.send).toBe('function');
    ws.close();
  });

  it('has close method', () => {
    const ws = new WebSocketShim('wss://localhost:9999/test');
    ws.on('error', () => {}); // Suppress expected errors
    expect(typeof ws.close).toBe('function');
    ws.close();
  });

  it('has readyState property', () => {
    const ws = new WebSocketShim('wss://localhost:9999/test');
    ws.on('error', () => {}); // Suppress expected errors
    expect(typeof ws.readyState).toBe('number');
    ws.close();
  });

  it('has binaryType property defaulting to arraybuffer', () => {
    const ws = new WebSocketShim('wss://localhost:9999/test');
    ws.on('error', () => {}); // Suppress expected errors
    expect(ws.binaryType).toBe('arraybuffer');
    ws.close();
  });
});

describe('Native WebSocket availability', () => {
  it('WebSocket is available in browser', () => {
    expect(typeof WebSocket).toBe('function');
  });

  it('can create native WebSocket', () => {
    // Just test that the constructor exists and doesn't throw on instantiation
    expect(() => {
      const ws = new WebSocket('wss://localhost:9999/test');
      ws.onerror = () => {}; // Suppress expected errors
      ws.close();
    }).not.toThrow();
  });
});
