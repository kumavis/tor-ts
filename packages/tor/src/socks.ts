/**
 * SOCKS5 proxy server implementation for Tor circuits.
 *
 * This module provides a SOCKS5 proxy server that routes connections through
 * Tor circuits. It supports:
 * - SOCKS5 CONNECT command
 * - IPv4, IPv6, and domain name addresses
 * - No-authentication method
 *
 * References:
 * - RFC 1928: SOCKS Protocol Version 5
 * - RFC 1929: Username/Password Authentication for SOCKS V5
 */

import net from 'node:net';
import { EventEmitter } from 'node:events';
import type { Circuit, CircuitStream } from './circuit.ts';

// SOCKS5 constants
export const SOCKS_VERSION = 0x05;

// Authentication methods
export enum SocksAuthMethod {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  USERNAME_PASSWORD = 0x02,
  NO_ACCEPTABLE = 0xff,
}

// SOCKS5 commands
export enum SocksCommand {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}

// SOCKS5 address types
export enum SocksAddressType {
  IPv4 = 0x01,
  DOMAIN = 0x03,
  IPv6 = 0x04,
}

// SOCKS5 reply codes
export enum SocksReply {
  SUCCEEDED = 0x00,
  GENERAL_FAILURE = 0x01,
  CONNECTION_NOT_ALLOWED = 0x02,
  NETWORK_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONNECTION_REFUSED = 0x05,
  TTL_EXPIRED = 0x06,
  COMMAND_NOT_SUPPORTED = 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
}

/**
 * Parsed SOCKS5 connection request
 */
export interface SocksRequest {
  version: number;
  command: SocksCommand;
  addressType: SocksAddressType;
  destinationAddress: string;
  destinationPort: number;
}

/**
 * Parse a SOCKS5 greeting (client's initial message)
 * Returns the list of authentication methods offered by the client.
 */
export function parseSocksGreeting(data: Buffer): {
  version: number;
  methods: SocksAuthMethod[];
} {
  if (data.length < 2) {
    throw new Error('SOCKS greeting too short');
  }

  const version = data.readUInt8(0);
  if (version !== SOCKS_VERSION) {
    throw new Error(`Unsupported SOCKS version: ${version}`);
  }

  const numMethods = data.readUInt8(1);
  if (data.length < 2 + numMethods) {
    throw new Error('SOCKS greeting truncated');
  }

  const methods: SocksAuthMethod[] = [];
  for (let i = 0; i < numMethods; i++) {
    methods.push(data.readUInt8(2 + i) as SocksAuthMethod);
  }

  return { version, methods };
}

/**
 * Build a SOCKS5 greeting response (server's method selection)
 */
export function buildSocksGreetingResponse(method: SocksAuthMethod): Buffer {
  return Buffer.from([SOCKS_VERSION, method]);
}

/**
 * Parse a SOCKS5 connection request
 */
export function parseSocksRequest(data: Buffer): SocksRequest {
  if (data.length < 4) {
    throw new Error('SOCKS request too short');
  }

  const version = data.readUInt8(0);
  if (version !== SOCKS_VERSION) {
    throw new Error(`Unsupported SOCKS version: ${version}`);
  }

  const command = data.readUInt8(1) as SocksCommand;
  // data[2] is reserved (0x00)
  const addressType = data.readUInt8(3) as SocksAddressType;

  let destinationAddress: string;
  let portOffset: number;

  switch (addressType) {
    case SocksAddressType.IPv4: {
      if (data.length < 10) {
        throw new Error('SOCKS request too short for IPv4');
      }
      destinationAddress = `${data.readUInt8(4)}.${data.readUInt8(5)}.${data.readUInt8(6)}.${data.readUInt8(7)}`;
      portOffset = 8;
      break;
    }
    case SocksAddressType.DOMAIN: {
      const domainLength = data.readUInt8(4);
      if (data.length < 5 + domainLength + 2) {
        throw new Error('SOCKS request too short for domain');
      }
      destinationAddress = data.subarray(5, 5 + domainLength).toString('ascii');
      portOffset = 5 + domainLength;
      break;
    }
    case SocksAddressType.IPv6: {
      if (data.length < 22) {
        throw new Error('SOCKS request too short for IPv6');
      }
      // Format as colon-separated hex groups
      const parts: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(data.readUInt16BE(4 + i).toString(16));
      }
      destinationAddress = parts.join(':');
      portOffset = 20;
      break;
    }
    default:
      throw new Error(`Unsupported address type: ${addressType}`);
  }

  const destinationPort = data.readUInt16BE(portOffset);

  return {
    version,
    command,
    addressType,
    destinationAddress,
    destinationPort,
  };
}

/**
 * Build a SOCKS5 reply
 */
export function buildSocksReply(
  reply: SocksReply,
  boundAddress: string = '0.0.0.0',
  boundPort: number = 0
): Buffer {
  // For simplicity, always respond with IPv4 bound address
  const addressParts = boundAddress.split('.').map((p) => parseInt(p, 10));
  const p0 = addressParts[0];
  const p1 = addressParts[1];
  const p2 = addressParts[2];
  const p3 = addressParts[3];
  if (
    addressParts.length !== 4 ||
    p0 === undefined ||
    p1 === undefined ||
    p2 === undefined ||
    p3 === undefined ||
    isNaN(p0) ||
    isNaN(p1) ||
    isNaN(p2) ||
    isNaN(p3)
  ) {
    // Use 0.0.0.0 as fallback
    return Buffer.from([
      SOCKS_VERSION,
      reply,
      0x00, // reserved
      SocksAddressType.IPv4,
      0,
      0,
      0,
      0,
      (boundPort >> 8) & 0xff,
      boundPort & 0xff,
    ]);
  }

  return Buffer.from([
    SOCKS_VERSION,
    reply,
    0x00, // reserved
    SocksAddressType.IPv4,
    p0,
    p1,
    p2,
    p3,
    (boundPort >> 8) & 0xff,
    boundPort & 0xff,
  ]);
}

/**
 * SOCKS5 client connection state machine
 */
enum SocksClientState {
  WAITING_GREETING = 'WAITING_GREETING',
  WAITING_REQUEST = 'WAITING_REQUEST',
  CONNECTED = 'CONNECTED',
  CLOSED = 'CLOSED',
}

/**
 * Options for creating a SOCKS proxy server
 */
export interface SocksServerOptions {
  /** The Tor circuit to use for connections */
  circuit: Circuit;
  /** Port to listen on (default: 1080) */
  port?: number;
  /** Host to bind to (default: '127.0.0.1') */
  host?: string;
}

/**
 * SOCKS5 proxy server that routes connections through a Tor circuit
 */
export class SocksProxyServer extends EventEmitter {
  private server: net.Server;
  private circuit: Circuit;
  private port: number;
  private host: string;
  private connections: Set<net.Socket> = new Set();

  constructor(options: SocksServerOptions) {
    super();
    this.circuit = options.circuit;
    this.port = options.port ?? 1080;
    this.host = options.host ?? '127.0.0.1';
    this.server = net.createServer((socket) => this.handleConnection(socket));

    this.server.on('error', (err) => {
      this.emit('error', err);
    });
  }

  /**
   * Start the SOCKS proxy server
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject);
        this.emit('listening', { port: this.port, host: this.host });
        resolve();
      });
    });
  }

  /**
   * Stop the SOCKS proxy server
   */
  async stop(): Promise<void> {
    // Close all active connections
    for (const socket of this.connections) {
      socket.destroy();
    }
    this.connections.clear();

    return new Promise((resolve) => {
      this.server.close(() => {
        this.emit('close');
        resolve();
      });
    });
  }

  /**
   * Get the address the server is listening on
   */
  address(): net.AddressInfo | string | null {
    return this.server.address();
  }

  private handleConnection(socket: net.Socket): void {
    this.connections.add(socket);
    let state = SocksClientState.WAITING_GREETING;
    let circuitStream: CircuitStream | undefined;
    let buffer = Buffer.alloc(0);

    const cleanup = () => {
      this.connections.delete(socket);
      if (circuitStream && !circuitStream.destroyed) {
        circuitStream.destroy();
      }
    };

    socket.on('close', cleanup);
    socket.on('error', (err) => {
      this.emit('connectionError', err);
      cleanup();
    });

    socket.on('data', async (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);

      try {
        if (state === SocksClientState.WAITING_GREETING) {
          // Parse greeting
          const greeting = parseSocksGreeting(buffer);

          // Check if NO_AUTH is supported
          if (!greeting.methods.includes(SocksAuthMethod.NO_AUTH)) {
            socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE));
            socket.end();
            return;
          }

          // Accept NO_AUTH
          socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_AUTH));
          buffer = Buffer.alloc(0);
          state = SocksClientState.WAITING_REQUEST;
        } else if (state === SocksClientState.WAITING_REQUEST) {
          // Parse request
          const request = parseSocksRequest(buffer);

          // Only CONNECT is supported
          if (request.command !== SocksCommand.CONNECT) {
            socket.write(buildSocksReply(SocksReply.COMMAND_NOT_SUPPORTED));
            socket.end();
            return;
          }

          // Open Tor stream to destination
          const destination = `${request.destinationAddress}:${request.destinationPort}`;
          this.emit('connect', { destination, socket });

          try {
            circuitStream = await this.circuit.open(destination);
            state = SocksClientState.CONNECTED;

            // Send success reply
            socket.write(buildSocksReply(SocksReply.SUCCEEDED));
            buffer = Buffer.alloc(0);

            // Relay data between socket and circuit stream
            this.setupRelay(socket, circuitStream);
          } catch (err) {
            console.error('Failed to open Tor stream:', err);
            socket.write(buildSocksReply(SocksReply.HOST_UNREACHABLE));
            socket.end();
          }
        } else if (state === SocksClientState.CONNECTED) {
          // After SOCKS handshake, relay data to circuit stream
          if (circuitStream) {
            await circuitStream.write(buffer);
            buffer = Buffer.alloc(0);
          }
        }
      } catch (err) {
        console.error('SOCKS protocol error:', err);
        socket.write(buildSocksReply(SocksReply.GENERAL_FAILURE));
        socket.end();
      }
    });
  }

  private setupRelay(socket: net.Socket, circuitStream: CircuitStream): void {
    // Data from circuit to client
    circuitStream.on('data', (data: Buffer) => {
      if (!socket.destroyed) {
        socket.write(data);
      }
    });

    // Circuit stream ended
    circuitStream.on('end', () => {
      if (!socket.destroyed) {
        socket.end();
      }
    });

    // Circuit stream error
    circuitStream.on('error', (err) => {
      console.error('Circuit stream error:', err);
      if (!socket.destroyed) {
        socket.destroy();
      }
    });

    // Socket closed
    socket.on('close', () => {
      if (!circuitStream.destroyed) {
        circuitStream.destroy();
      }
    });
  }
}

/**
 * Create and start a SOCKS proxy server
 */
export async function createSocksProxy(options: SocksServerOptions): Promise<SocksProxyServer> {
  const server = new SocksProxyServer(options);
  await server.start();
  return server;
}
