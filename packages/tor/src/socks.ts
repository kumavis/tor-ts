/**
 * SOCKS5 proxy server that routes connections through a Tor circuit.
 *
 * RFC 1928 (SOCKS Protocol Version 5). Only the CONNECT command and
 * the NO_AUTH method are implemented; that's the same subset the
 * upstream Tor client exposes on its SocksPort and is enough to plug
 * existing tooling (curl, browsers, etc.) into the in-process stack.
 *
 * Flow per accepted client connection:
 *   1. Wait for the SOCKS5 greeting; reply with NO_AUTH or NO_ACCEPTABLE.
 *   2. Wait for the CONNECT request; open a stream on the supplied circuit.
 *   3. Reply with SUCCEEDED and bidirectionally relay bytes between the
 *      TCP socket and the {@link CircuitStream} until either side closes.
 */

import net, { isIPv4, isIPv6 } from 'node:net';
import { EventEmitter } from 'node:events';

import type { Circuit, CircuitStream } from './circuit.ts';

export const SOCKS_VERSION = 0x05;

export enum SocksAuthMethod {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  USERNAME_PASSWORD = 0x02,
  NO_ACCEPTABLE = 0xff,
}

export enum SocksCommand {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}

export enum SocksAddressType {
  IPv4 = 0x01,
  DOMAIN = 0x03,
  IPv6 = 0x04,
}

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

/** Parsed SOCKS5 connection request. */
export interface SocksRequest {
  version: number;
  command: SocksCommand;
  addressType: SocksAddressType;
  destinationAddress: string;
  destinationPort: number;
}

/** Parsed SOCKS5 client greeting. */
export interface SocksGreeting {
  version: number;
  methods: SocksAuthMethod[];
}

/**
 * Parse a SOCKS5 client greeting:
 *
 *   +----+----------+----------+
 *   |VER | NMETHODS | METHODS  |
 *   +----+----------+----------+
 *   | 1  |    1     | 1 to 255 |
 *   +----+----------+----------+
 */
export function parseSocksGreeting(data: Buffer): SocksGreeting {
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
 * Total byte length of a SOCKS5 greeting frame given a buffer that contains
 * at least the first two bytes; returns `undefined` if the frame isn't
 * complete yet.
 */
export function socksGreetingFrameLength(data: Buffer): number | undefined {
  if (data.length < 2) return undefined;
  const numMethods = data.readUInt8(1);
  const total = 2 + numMethods;
  return data.length >= total ? total : undefined;
}

/** Build the server's reply to the greeting (single chosen method). */
export function buildSocksGreetingResponse(method: SocksAuthMethod): Buffer {
  return Buffer.from([SOCKS_VERSION, method]);
}

/**
 * Parse a SOCKS5 request:
 *
 *   +----+-----+-------+------+----------+----------+
 *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *   +----+-----+-------+------+----------+----------+
 *   | 1  |  1  | X'00' |  1   | Variable |    2     |
 *   +----+-----+-------+------+----------+----------+
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
  // data[2] is the reserved 0x00 byte
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
      if (data.length < 5) {
        throw new Error('SOCKS request too short for domain');
      }
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
  return { version, command, addressType, destinationAddress, destinationPort };
}

/**
 * Total byte length of a SOCKS5 request frame given a buffer that contains
 * at least the first 4 (or 5, for DOMAIN) bytes; returns `undefined` if the
 * frame isn't complete yet.
 */
export function socksRequestFrameLength(data: Buffer): number | undefined {
  if (data.length < 4) return undefined;
  const addressType = data.readUInt8(3) as SocksAddressType;
  let total: number;
  switch (addressType) {
    case SocksAddressType.IPv4:
      total = 4 + 4 + 2;
      break;
    case SocksAddressType.IPv6:
      total = 4 + 16 + 2;
      break;
    case SocksAddressType.DOMAIN: {
      if (data.length < 5) return undefined;
      const domainLength = data.readUInt8(4);
      total = 4 + 1 + domainLength + 2;
      break;
    }
    default:
      // Caller will fail with ADDRESS_TYPE_NOT_SUPPORTED once the
      // 4-byte header is parsed; returning the header length here keeps
      // the caller from waiting on additional bytes that will never come.
      return 4;
  }
  return data.length >= total ? total : undefined;
}

/**
 * Build a SOCKS5 reply. The bound-address fields are only meaningful when
 * the client cares about them (e.g. for BIND); for CONNECT the spec lets
 * us answer with the all-zeros IPv4 address, which is what we do unless
 * the caller passes a real bound address.
 */
export function buildSocksReply(
  reply: SocksReply,
  boundAddress: string = '0.0.0.0',
  boundPort: number = 0
): Buffer {
  const portHi = (boundPort >> 8) & 0xff;
  const portLo = boundPort & 0xff;

  // Always reply with an IPv4 bound-address; that matches the upstream
  // tor SocksPort behaviour and is sufficient for CONNECT.
  const parts = boundAddress.split('.').map((p) => parseInt(p, 10));
  const [p0, p1, p2, p3] = parts;
  const isValidIPv4 =
    parts.length === 4 &&
    p0 !== undefined &&
    p1 !== undefined &&
    p2 !== undefined &&
    p3 !== undefined &&
    !isNaN(p0) &&
    !isNaN(p1) &&
    !isNaN(p2) &&
    !isNaN(p3);

  return Buffer.from([
    SOCKS_VERSION,
    reply,
    0x00, // reserved
    SocksAddressType.IPv4,
    isValidIPv4 ? (p0 as number) : 0,
    isValidIPv4 ? (p1 as number) : 0,
    isValidIPv4 ? (p2 as number) : 0,
    isValidIPv4 ? (p3 as number) : 0,
    portHi,
    portLo,
  ]);
}

/**
 * Translate a Node `net.connect`-style error code into the closest
 * matching SOCKS5 reply code. Used so that downstream tooling can
 * distinguish "host doesn't exist" from "exit relay refused".
 */
export function socksReplyForOpenError(err: unknown): SocksReply {
  const code = (err as { code?: string } | null)?.code;
  if (code === 'ENETUNREACH') return SocksReply.NETWORK_UNREACHABLE;
  if (code === 'ECONNREFUSED') return SocksReply.CONNECTION_REFUSED;
  if (code === 'EHOSTUNREACH') return SocksReply.HOST_UNREACHABLE;
  return SocksReply.HOST_UNREACHABLE;
}

/** Options for {@link SocksProxyServer}. */
export interface SocksServerOptions {
  /**
   * The Tor circuit to use for outbound connections. Each accepted SOCKS
   * client opens its own {@link CircuitStream} on this circuit; the caller
   * owns the circuit's lifetime.
   */
  circuit: Circuit;
  /** Port to listen on. Default: 1080. */
  port?: number;
  /** Host to bind to. Default: '127.0.0.1'. */
  host?: string;
}

/**
 * Format a SOCKS5 destination address + port into the `addr:port` form the
 * Tor BEGIN cell expects. Wraps IPv6 literals in brackets so the colons in
 * the address aren't ambiguous with the port separator.
 */
export function formatTorDestination(addr: string, port: number): string {
  if (isIPv6(addr)) return `[${addr}]:${port}`;
  return `${addr}:${port}`;
}

const enum ConnectionPhase {
  Greeting,
  Request,
  Connecting,
  Relaying,
  Closed,
}

/**
 * SOCKS5 proxy server that routes accepted connections through a single
 * shared Tor {@link Circuit}.
 *
 * Lifecycle: caller constructs with a connected circuit, awaits
 * {@link start}, and {@link stop}s when finished. The circuit itself is
 * owned by the caller; the server only opens streams on it and never
 * destroys it.
 */
export class SocksProxyServer extends EventEmitter {
  private readonly server: net.Server;
  private readonly circuit: Circuit;
  private readonly port: number;
  private readonly host: string;
  private readonly connections = new Set<net.Socket>();

  constructor(options: SocksServerOptions) {
    super();
    this.circuit = options.circuit;
    this.port = options.port ?? 1080;
    this.host = options.host ?? '127.0.0.1';
    this.server = net.createServer((socket) => this.handleConnection(socket));
    this.server.on('error', (err) => this.emit('error', err));
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => {
        this.server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        this.server.removeListener('error', onError);
        resolve();
      };
      this.server.once('error', onError);
      this.server.once('listening', onListening);
      this.server.listen(this.port, this.host);
    });
    const addr = this.server.address();
    this.emit('listening', addr);
  }

  async stop(): Promise<void> {
    for (const socket of this.connections) {
      socket.destroy();
    }
    this.connections.clear();
    await new Promise<void>((resolve) => {
      this.server.close(() => {
        this.emit('close');
        resolve();
      });
    });
  }

  /** The address the server is bound to, or `null` if not yet listening. */
  address(): net.AddressInfo | string | null {
    return this.server.address();
  }

  private handleConnection(socket: net.Socket): void {
    this.connections.add(socket);

    let phase: ConnectionPhase = ConnectionPhase.Greeting;
    let buffer = Buffer.alloc(0);
    let circuitStream: CircuitStream | undefined;
    // Serialize writes from the socket onto the (async) circuit stream so
    // chunks aren't reordered by interleaved awaits, and so backpressure
    // applies as a single chain rather than per-event.
    let writeChain: Promise<void> = Promise.resolve();

    const closeAll = (err?: Error) => {
      if (phase === ConnectionPhase.Closed) return;
      phase = ConnectionPhase.Closed;
      this.connections.delete(socket);
      if (!socket.destroyed) {
        if (err) socket.destroy(err);
        else socket.destroy();
      }
      if (circuitStream && !circuitStream.destroyed) {
        circuitStream.destroy();
      }
    };

    socket.on('error', (err) => {
      this.emit('connectionError', err);
      closeAll(err);
    });
    socket.on('close', () => closeAll());

    const replyFatal = (reply: SocksReply) => {
      if (!socket.destroyed) {
        socket.write(buildSocksReply(reply));
        socket.end();
      }
    };

    socket.on('data', (chunk: Buffer) => {
      if (phase === ConnectionPhase.Closed) return;

      // Once we're relaying, hand each chunk off to the circuit-stream
      // writer chain. Pause the socket while a write is in flight so the
      // OS-level buffer applies backpressure to the SOCKS client when
      // the circuit is slow.
      if (phase === ConnectionPhase.Relaying) {
        if (!circuitStream || circuitStream.destroyed) {
          closeAll();
          return;
        }
        const cs = circuitStream;
        socket.pause();
        writeChain = writeChain.then(
          () =>
            cs.write(chunk).then(
              () => {
                if (!socket.destroyed) socket.resume();
              },
              (err: Error) => {
                this.emit('connectionError', err);
                closeAll(err);
              }
            ),
          () => {
            // Previous write already failed; nothing to do.
          }
        );
        return;
      }

      buffer = Buffer.concat([buffer, chunk]);

      try {
        if (phase === ConnectionPhase.Greeting) {
          const total = socksGreetingFrameLength(buffer);
          if (total === undefined) return; // wait for more
          const greeting = parseSocksGreeting(buffer.subarray(0, total));
          buffer = buffer.subarray(total);

          if (!greeting.methods.includes(SocksAuthMethod.NO_AUTH)) {
            socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE));
            socket.end();
            return;
          }
          socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_AUTH));
          phase = ConnectionPhase.Request;
          // fall through: there may already be request bytes in `buffer`
        }

        if (phase === ConnectionPhase.Request) {
          const total = socksRequestFrameLength(buffer);
          if (total === undefined) return; // wait for more
          const request = parseSocksRequest(buffer.subarray(0, total));
          buffer = buffer.subarray(total);

          if (request.command !== SocksCommand.CONNECT) {
            replyFatal(SocksReply.COMMAND_NOT_SUPPORTED);
            return;
          }
          if (
            request.addressType === SocksAddressType.IPv4 &&
            !isIPv4(request.destinationAddress)
          ) {
            replyFatal(SocksReply.ADDRESS_TYPE_NOT_SUPPORTED);
            return;
          }
          if (
            request.addressType === SocksAddressType.IPv6 &&
            !isIPv6(request.destinationAddress)
          ) {
            replyFatal(SocksReply.ADDRESS_TYPE_NOT_SUPPORTED);
            return;
          }

          const destination = formatTorDestination(
            request.destinationAddress,
            request.destinationPort
          );
          this.emit('connect', { destination, request, socket });
          phase = ConnectionPhase.Connecting;

          // Pause the socket while we open a Tor stream so any extra bytes
          // the client speculatively sends don't show up as 'data' events
          // on a half-built circuit stream.
          socket.pause();
          this.openCircuitStream(socket, destination)
            .then((stream) => {
              if (phase === ConnectionPhase.Closed) {
                stream.destroy();
                return;
              }
              circuitStream = stream;
              this.setupRelay(socket, stream, closeAll);
              if (!socket.destroyed) {
                socket.write(buildSocksReply(SocksReply.SUCCEEDED));
              }
              phase = ConnectionPhase.Relaying;
              if (!socket.destroyed) socket.resume();

              // If the client speculatively pipelined bytes after the
              // request, replay them through the relay path now.
              if (buffer.length > 0) {
                const pipelined = buffer;
                buffer = Buffer.alloc(0);
                writeChain = writeChain.then(
                  () =>
                    stream.write(pipelined).catch((err: Error) => {
                      this.emit('connectionError', err);
                      closeAll(err);
                    }),
                  () => {}
                );
              }
            })
            .catch((err: Error) => {
              this.emit('connectionError', err);
              if (!socket.destroyed) {
                socket.write(buildSocksReply(socksReplyForOpenError(err)));
                socket.end();
              }
              closeAll();
            });
        }
      } catch (err) {
        this.emit('connectionError', err as Error);
        replyFatal(SocksReply.GENERAL_FAILURE);
        closeAll();
      }
    });
  }

  /**
   * Open a Tor stream for the destination requested by a SOCKS client.
   * Pulled out so tests can substitute a fake circuit without monkey-patching.
   */
  protected openCircuitStream(_socket: net.Socket, destination: string): Promise<CircuitStream> {
    return this.circuit.open(destination);
  }

  private setupRelay(
    socket: net.Socket,
    circuitStream: CircuitStream,
    closeAll: (err?: Error) => void
  ): void {
    circuitStream.on('data', (data: Buffer) => {
      if (socket.destroyed) return;
      socket.write(data);
    });
    circuitStream.on('end', () => {
      if (!socket.destroyed) socket.end();
    });
    circuitStream.on('error', (err: Error) => {
      this.emit('connectionError', err);
      closeAll(err);
    });
  }
}

/** Construct and start a {@link SocksProxyServer} in one call. */
export async function createSocksProxy(options: SocksServerOptions): Promise<SocksProxyServer> {
  const server = new SocksProxyServer(options);
  await server.start();
  return server;
}
