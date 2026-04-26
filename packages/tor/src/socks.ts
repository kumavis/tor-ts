/**
 * SOCKS5 proxy server that routes connections through a Tor circuit.
 *
 * RFC 1928 (SOCKS Protocol Version 5) + RFC 1929 (Username/Password
 * sub-negotiation). Only the CONNECT command is implemented; that's the
 * same subset c-tor's SocksPort and Arti both expose for plain proxying.
 *
 * SOCKS5 username/password is **not** treated as authentication — c-tor
 * and Arti both repurpose it as a stream-isolation key, and that's how
 * we surface it here too: the parsed `SocksAuth` is handed to the
 * caller-supplied {@link SocksCircuitFactory} (or to the `'connect'`
 * event), and the caller decides whether to map it onto a fresh circuit,
 * a circuit-pool slot, or just ignore it.
 *
 * Flow per accepted client connection:
 *   1. Wait for the SOCKS5 greeting; pick NO_AUTH if offered, else fall
 *      back to USERNAME_PASSWORD (RFC 1929) and parse the credentials.
 *   2. Wait for the CONNECT request; ask the configured circuit provider
 *      for a circuit, then open a stream on it.
 *   3. Reply with SUCCEEDED and bidirectionally relay bytes between the
 *      TCP socket and the {@link CircuitStream} until either side closes.
 */

import net, { isIPv4, isIPv6 } from 'node:net';
import { EventEmitter } from 'node:events';

import type { Circuit, CircuitStream } from './circuit.ts';
import { RelayEndError, RelayEndReasons } from './relay-cell.ts';

export const SOCKS_VERSION = 0x05;

/** RFC 1929 username/password sub-negotiation version byte. */
export const SOCKS_USERPASS_VERSION = 0x01;

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
 * Parsed RFC 1929 credentials. Tor never authenticates these — they're
 * the SOCKS-level isolation key, equivalent to c-tor's `ISO_SOCKSAUTH`
 * and Arti's `SocksAuth::Username` field. Exposed as raw bytes so we
 * don't accidentally mangle non-UTF-8 bytes that a tooling-side
 * isolation hash relies on.
 */
export interface SocksAuth {
  username: Buffer;
  password: Buffer;
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
 * Parse an RFC 1929 username/password sub-negotiation message:
 *
 *   +----+------+----------+------+----------+
 *   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *   +----+------+----------+------+----------+
 *   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *   +----+------+----------+------+----------+
 *
 * `VER` is the sub-negotiation version (0x01), distinct from the SOCKS5
 * protocol version (0x05) — clients that get this wrong are common
 * enough that we error explicitly.
 */
export function parseSocksUserPass(data: Buffer): SocksAuth {
  if (data.length < 2) {
    throw new Error('SOCKS user/pass too short');
  }
  const version = data.readUInt8(0);
  if (version !== SOCKS_USERPASS_VERSION) {
    throw new Error(`Unsupported SOCKS user/pass version: ${version}`);
  }
  const ulen = data.readUInt8(1);
  if (data.length < 2 + ulen + 1) {
    throw new Error('SOCKS user/pass truncated (UNAME/PLEN)');
  }
  const username = Buffer.from(data.subarray(2, 2 + ulen));
  const plen = data.readUInt8(2 + ulen);
  if (data.length < 2 + ulen + 1 + plen) {
    throw new Error('SOCKS user/pass truncated (PASSWD)');
  }
  const password = Buffer.from(data.subarray(2 + ulen + 1, 2 + ulen + 1 + plen));
  return { username, password };
}

/**
 * Total byte length of an RFC 1929 user/pass frame given a buffer that
 * contains the prefix; returns `undefined` if the frame isn't complete yet.
 */
export function socksUserPassFrameLength(data: Buffer): number | undefined {
  if (data.length < 2) return undefined;
  const ulen = data.readUInt8(1);
  const plenOffset = 2 + ulen;
  if (data.length < plenOffset + 1) return undefined;
  const plen = data.readUInt8(plenOffset);
  const total = plenOffset + 1 + plen;
  return data.length >= total ? total : undefined;
}

/**
 * Build an RFC 1929 sub-negotiation reply. Tor always returns success here
 * (`status = 0`), even with empty username/password — these are isolation
 * keys, not credentials.
 */
export function buildSocksUserPassResponse(status: number = 0): Buffer {
  return Buffer.from([SOCKS_USERPASS_VERSION, status & 0xff]);
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
 * Translate a Tor RELAY_END `reason` byte into the closest matching SOCKS5
 * reply code. Mirrors c-tor's `reasons.c::stream_end_reason_to_socks5_response`
 * (see https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/core/or/reasons.c).
 *
 * Reasons not listed map to `GENERAL_FAILURE` so tooling never sees a bare
 * number it can't display.
 */
export function socksReplyForRelayEndReason(reason: number): SocksReply {
  switch (reason) {
    case RelayEndReasons.REASON_RESOLVEFAILED:
      return SocksReply.HOST_UNREACHABLE;
    case RelayEndReasons.REASON_CONNECTREFUSED:
      return SocksReply.CONNECTION_REFUSED;
    case RelayEndReasons.REASON_EXITPOLICY:
      return SocksReply.CONNECTION_NOT_ALLOWED;
    case RelayEndReasons.REASON_TIMEOUT:
      return SocksReply.TTL_EXPIRED;
    case RelayEndReasons.REASON_NOROUTE:
      return SocksReply.NETWORK_UNREACHABLE;
    case RelayEndReasons.REASON_MISC:
    case RelayEndReasons.REASON_DESTROY:
    case RelayEndReasons.REASON_DONE:
    case RelayEndReasons.REASON_HIBERNATING:
    case RelayEndReasons.REASON_INTERNAL:
    case RelayEndReasons.REASON_RESOURCELIMIT:
    case RelayEndReasons.REASON_CONNRESET:
    case RelayEndReasons.REASON_TORPROTOCOL:
    case RelayEndReasons.REASON_NOTDIRECTORY:
      return SocksReply.GENERAL_FAILURE;
    default:
      return SocksReply.GENERAL_FAILURE;
  }
}

/**
 * Map an error from `circuit.open()` (or any failure during the SOCKS-side
 * stream-establishment path) onto a SOCKS5 reply code. Checks for
 * {@link RelayEndError} first (Tor-side failures, the most specific
 * signal), then falls back to Node-style network error codes
 * (`ECONNREFUSED`, `EHOSTUNREACH`, `ENETUNREACH`, `ETIMEDOUT`).
 */
export function socksReplyForOpenError(err: unknown): SocksReply {
  if (err instanceof RelayEndError) {
    return socksReplyForRelayEndReason(err.reason);
  }
  const code = (err as { code?: string } | null)?.code;
  if (code === 'ENETUNREACH') return SocksReply.NETWORK_UNREACHABLE;
  if (code === 'ECONNREFUSED') return SocksReply.CONNECTION_REFUSED;
  if (code === 'EHOSTUNREACH') return SocksReply.HOST_UNREACHABLE;
  if (code === 'ETIMEDOUT') return SocksReply.TTL_EXPIRED;
  return SocksReply.HOST_UNREACHABLE;
}

/**
 * Context passed to a {@link SocksCircuitFactory}. Includes the parsed
 * CONNECT request and any RFC 1929 credentials the client sent. The
 * factory is the canonical place to implement stream isolation: derive
 * a key from `auth` (and/or `request.destinationAddress`) and pick or
 * build a circuit accordingly.
 */
export interface SocksConnectionContext {
  request: SocksRequest;
  auth?: SocksAuth;
}

/**
 * Per-connection circuit provider. Called once per accepted SOCKS
 * connection, after the request has been parsed but before the BEGIN
 * cell is sent. The returned circuit is used for that one connection;
 * its lifetime stays with the caller — {@link SocksProxyServer} never
 * destroys circuits it didn't create.
 */
export type SocksCircuitFactory = (ctx: SocksConnectionContext) => Promise<Circuit>;

/** Options for {@link SocksProxyServer}. */
export interface SocksServerOptions {
  /**
   * A single shared Tor circuit. Every accepted SOCKS connection opens
   * its own {@link CircuitStream} on this circuit. Mutually exclusive
   * with {@link SocksServerOptions.circuitFactory}.
   */
  circuit?: Circuit;
  /**
   * Per-connection circuit factory — equivalent to c-tor's stream
   * isolation knob. Receives the parsed request and the client's RFC
   * 1929 credentials (if any) and returns the circuit to use.
   * Mutually exclusive with {@link SocksServerOptions.circuit}.
   */
  circuitFactory?: SocksCircuitFactory;
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
  Auth,
  Request,
  Connecting,
  Relaying,
  Closed,
}

/**
 * SOCKS5 proxy server that routes accepted connections through a Tor
 * {@link Circuit}. The circuit can be a single shared one (passed via
 * `options.circuit`) or supplied per connection by a factory
 * (`options.circuitFactory`) — the latter is how callers implement
 * stream isolation.
 *
 * Lifecycle: caller constructs, awaits {@link start}, and {@link stop}s
 * when finished. Circuits handed to or returned by the server are owned
 * by the caller; the server only opens streams on them and never
 * destroys them itself.
 */
export class SocksProxyServer extends EventEmitter {
  private readonly server: net.Server;
  private readonly circuitProvider: SocksCircuitFactory;
  private readonly port: number;
  private readonly host: string;
  private readonly connections = new Set<net.Socket>();

  constructor(options: SocksServerOptions) {
    super();
    if (options.circuit && options.circuitFactory) {
      throw new Error('SocksServerOptions: pass either `circuit` or `circuitFactory`, not both');
    }
    if (options.circuit) {
      const circuit = options.circuit;
      this.circuitProvider = async () => circuit;
    } else if (options.circuitFactory) {
      this.circuitProvider = options.circuitFactory;
    } else {
      throw new Error('SocksServerOptions: either `circuit` or `circuitFactory` is required');
    }
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
    let auth: SocksAuth | undefined;
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

          // Prefer NO_AUTH (matches c-tor's `socks_prefer_no_auth`).
          // Fall back to USERNAME_PASSWORD so clients that always
          // advertise it for stream isolation (Tor Browser, torsocks
          // with isolation flags) don't get rejected.
          if (greeting.methods.includes(SocksAuthMethod.NO_AUTH)) {
            socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_AUTH));
            phase = ConnectionPhase.Request;
          } else if (greeting.methods.includes(SocksAuthMethod.USERNAME_PASSWORD)) {
            socket.write(buildSocksGreetingResponse(SocksAuthMethod.USERNAME_PASSWORD));
            phase = ConnectionPhase.Auth;
          } else {
            socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE));
            socket.end();
            return;
          }
          // fall through: the request (or sub-negotiation) bytes may
          // already be in `buffer`
        }

        if (phase === ConnectionPhase.Auth) {
          const total = socksUserPassFrameLength(buffer);
          if (total === undefined) return; // wait for more
          auth = parseSocksUserPass(buffer.subarray(0, total));
          buffer = buffer.subarray(total);
          // Tor never authenticates these — always succeed.
          socket.write(buildSocksUserPassResponse(0));
          phase = ConnectionPhase.Request;
          // fall through
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
          const ctx: SocksConnectionContext = auth ? { request, auth } : { request };
          this.emit('connect', { destination, request, auth, socket });
          phase = ConnectionPhase.Connecting;

          // Pause the socket while we open a Tor stream so any extra bytes
          // the client speculatively sends don't show up as 'data' events
          // on a half-built circuit stream.
          socket.pause();
          this.openStreamForConnection(ctx, destination)
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
   * Resolve the circuit for this connection (via the configured shared
   * circuit or factory) and open a stream to `destination`. Pulled out as
   * a single async step so the `'data'`-handler caller doesn't have to
   * thread two failure paths.
   */
  protected async openStreamForConnection(
    ctx: SocksConnectionContext,
    destination: string
  ): Promise<CircuitStream> {
    const circuit = await this.circuitProvider(ctx);
    return circuit.open(destination);
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
