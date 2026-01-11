/**
 * Browser shim for the 'ws' package.
 * Wraps native WebSocket to match the ws package API.
 */

import { EventEmitter } from 'events';

export type RawData = ArrayBuffer | Buffer | ArrayBuffer[] | string;

export default class WebSocketShim extends EventEmitter {
  private ws: WebSocket;
  binaryType: 'arraybuffer' | 'blob' = 'arraybuffer';

  constructor(url: string, _options?: { perMessageDeflate?: boolean }) {
    super();
    this.ws = new WebSocket(url);
    this.ws.binaryType = 'arraybuffer';

    this.ws.onopen = () => {
      this.emit('open');
    };

    this.ws.onmessage = (event: MessageEvent) => {
      this.emit('message', event.data);
    };

    this.ws.onclose = (event: CloseEvent) => {
      this.emit('close', event.code, event.reason);
    };

    this.ws.onerror = (event: Event) => {
      this.emit('error', new Error(`WebSocket error: ${event.type}`));
    };
  }

  send(data: string | ArrayBuffer | Uint8Array): void {
    this.ws.send(data);
  }

  close(code?: number, reason?: string): void {
    this.ws.close(code, reason);
  }

  get readyState(): number {
    return this.ws.readyState;
  }

  static get CONNECTING(): number {
    return WebSocket.CONNECTING;
  }
  static get OPEN(): number {
    return WebSocket.OPEN;
  }
  static get CLOSING(): number {
    return WebSocket.CLOSING;
  }
  static get CLOSED(): number {
    return WebSocket.CLOSED;
  }
}

export { WebSocketShim as WebSocket };
