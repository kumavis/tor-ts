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
import {
  RelayEndError,
  RelayEndReasons,
  RelayResolvedType,
  formatResolvedIPv4,
  formatResolvedIPv6,
  ipv4ToInAddrArpa,
  ipv6StringToBytes,
  ipv6ToIp6Arpa,
  type RelayResolvedRecord,
} from './relay-cell.ts';

export const SOCKS_VERSION = 0x05;

/** RFC 1929 username/password sub-negotiation version byte. */
export const SOCKS_USERPASS_VERSION = 0x01;

export enum SocksAuthMethod {
  NO_AUTH = 0x00,
  GSSAPI = 0x01,
  USERNAME_PASSWORD = 0x02,
  NO_ACCEPTABLE = 0xff,
}

/**
 * SOCKS5 command bytes. CONNECT/BIND/UDP_ASSOCIATE are RFC 1928; RESOLVE
 * and RESOLVE_PTR are Tor's proposal-100 extension that exposes anonymous
 * DNS over a circuit. c-tor and Arti both implement the same three:
 * CONNECT, RESOLVE, RESOLVE_PTR.
 */
export enum SocksCommand {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
  RESOLVE = 0xf0,
  RESOLVE_PTR = 0xf1,
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
  // RFC 1928: byte 2 is reserved and MUST be 0x00. Reject non-conforming
  // values rather than silently accepting them — masks parser bugs and
  // makes traffic-shape mismatches debuggable.
  const reserved = data.readUInt8(2);
  if (reserved !== 0x00) {
    throw new Error(`Invalid SOCKS reserved byte: ${reserved}`);
  }
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
 *
 * Always emits a 10-byte reply with `ATYP = IPv4`, regardless of input.
 * If `boundAddress` doesn't parse as a dotted-quad IPv4, the bound-address
 * fields silently fall back to `0.0.0.0` (the port byte is preserved).
 * Callers that need IPv6 / DOMAIN bound-addresses should use
 * {@link buildSocksTypedReply} instead — that helper validates strictly
 * and throws on malformed input.
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
  //
  // We delegate the validity check to `net.isIPv4` so anything outside
  // the dotted-quad form — including out-of-range octets like 999.0.0.1
  // — collapses to the 0.0.0.0 fallback rather than being silently
  // truncated mod-256 by `Buffer.from([..., 999, ...])`.
  const [p0, p1, p2, p3] = isIPv4(boundAddress)
    ? boundAddress.split('.').map((p) => parseInt(p, 10))
    : [0, 0, 0, 0];

  return Buffer.from([
    SOCKS_VERSION,
    reply,
    0x00, // reserved
    SocksAddressType.IPv4,
    p0!,
    p1!,
    p2!,
    p3!,
    portHi,
    portLo,
  ]);
}

/**
 * Build a SOCKS5 reply with an explicit bound-address type. Required when
 * answering RESOLVE (returns IPv4/IPv6) or RESOLVE_PTR (returns DOMAIN);
 * for plain CONNECT the simpler {@link buildSocksReply} (always IPv4) is
 * sufficient.
 */
export function buildSocksTypedReply(
  reply: SocksReply,
  bound:
    | { type: SocksAddressType.IPv4; address: string }
    | { type: SocksAddressType.IPv6; address: string }
    | { type: SocksAddressType.DOMAIN; address: string },
  boundPort: number = 0
): Buffer {
  const portHi = (boundPort >> 8) & 0xff;
  const portLo = boundPort & 0xff;

  switch (bound.type) {
    case SocksAddressType.IPv4: {
      const parts = bound.address.split('.').map((p) => parseInt(p, 10));
      if (parts.length !== 4 || parts.some((p) => !Number.isFinite(p) || p < 0 || p > 255)) {
        throw new Error(`Not a valid IPv4 address: ${bound.address}`);
      }
      return Buffer.from([
        SOCKS_VERSION,
        reply,
        0x00,
        SocksAddressType.IPv4,
        parts[0]!,
        parts[1]!,
        parts[2]!,
        parts[3]!,
        portHi,
        portLo,
      ]);
    }
    case SocksAddressType.IPv6: {
      const bytes = ipv6StringToBytes(bound.address);
      const out = Buffer.alloc(4 + 16 + 2);
      out[0] = SOCKS_VERSION;
      out[1] = reply;
      out[2] = 0x00;
      out[3] = SocksAddressType.IPv6;
      bytes.copy(out, 4);
      out.writeUInt16BE(boundPort, 20);
      return out;
    }
    case SocksAddressType.DOMAIN: {
      const addr = Buffer.from(bound.address, 'ascii');
      if (addr.length > 255) {
        throw new Error(`Domain address too long: ${addr.length} bytes`);
      }
      return Buffer.concat([
        Buffer.from([SOCKS_VERSION, reply, 0x00, SocksAddressType.DOMAIN, addr.length]),
        addr,
        Buffer.from([portHi, portLo]),
      ]);
    }
  }
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

// Plain enum (not `const enum`) so the symbol survives type-erasure transforms
// like Node's `--experimental-transform-types`, esbuild, and swc — `const enum`
// requires the consumer's toolchain to inline references at compile time, which
// not every consumer does.
enum ConnectionPhase {
  Greeting,
  Auth,
  Request,
  Connecting,
  Relaying,
  Closed,
}

/**
 * Maximum total bytes the SOCKS handshake buffer is allowed to hold. Real
 * SOCKS5 handshakes are bounded above at ~1 KiB (greeting ≤ 257, user/pass
 * sub-negotiation ≤ 513, request ≤ 262). 4 KiB is generous slack while still
 * giving us a hard cap against a misbehaving client that streams unbounded
 * data without ever completing a frame.
 */
const HANDSHAKE_BUFFER_LIMIT = 4 * 1024;

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

    // State cleanup is split from socket cleanup so the `'close'` listener
    // can run the state half *without* re-entering `socket.destroy()` (the
    // socket is already closing) — and so callers can safely invoke
    // `closeAll()` after a graceful `socket.end()` without racing the FIN
    // with a `destroy()`. `cleanupConnection` is one-shot: it returns true
    // the first time, false on every subsequent call.
    const cleanupConnection = (): boolean => {
      if (phase === ConnectionPhase.Closed) return false;
      phase = ConnectionPhase.Closed;
      this.connections.delete(socket);
      if (circuitStream && !circuitStream.destroyed) {
        circuitStream.destroy();
      }
      return true;
    };

    const closeAll = (err?: Error) => {
      if (!cleanupConnection()) return;
      if (socket.destroyed) return;
      if (err) {
        socket.destroy(err);
      } else if (!socket.writableEnded) {
        // Either nothing's been written yet or the catch path hasn't
        // half-closed; emit a graceful FIN. If `socket.end()` was already
        // called by the catch path, leave it alone — destroying after end
        // races the FIN off the wire.
        socket.end();
      }
    };

    socket.on('error', (err) => {
      this.emit('connectionError', err);
      closeAll(err);
    });
    socket.on('close', () => {
      // Socket already closed; just run the state half and skip any
      // further socket I/O.
      cleanupConnection();
    });

    /**
     * Send a fatal failure reply and close the socket. The wire format
     * the client expects depends on which phase we're in:
     *
     *   - Greeting   : 2-byte method-selection reply with NO_ACCEPTABLE.
     *                  Sending a 10-byte CONNECT-style reply here would be
     *                  misparsed (e.g. byte 1 = 0x01 → "GSSAPI selected").
     *   - Auth       : 2-byte RFC 1929 sub-negotiation status (failure).
     *   - Request &  : 10-byte CONNECT-shape reply with the supplied REP.
     *     beyond
     *
     * Pre-Request phases ignore the supplied REP byte (the spec doesn't
     * give us a way to surface it via the 2-byte responses), but it's
     * still useful to log / emit on `'connectionError'` for diagnostics.
     */
    const replyFatal = (reply: SocksReply) => {
      if (socket.destroyed) return;
      if (phase === ConnectionPhase.Greeting) {
        socket.write(buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE));
      } else if (phase === ConnectionPhase.Auth) {
        // Any non-zero status is a failure per RFC 1929; 0xff is unambiguous.
        socket.write(buildSocksUserPassResponse(0xff));
      } else {
        socket.write(buildSocksReply(reply));
      }
      socket.end();
    };

    /**
     * Append `chunk` to the handshake `buffer`, with a hard cap so a
     * misbehaving client can't grow it without bound (no complete frame =
     * no opportunity to drain). On overflow we close with a generic
     * failure REP — same shape as any other parse-time failure.
     */
    const appendToHandshakeBuffer = (chunk: Buffer): boolean => {
      if (buffer.length + chunk.length > HANDSHAKE_BUFFER_LIMIT) {
        this.emit(
          'connectionError',
          new Error(`SOCKS handshake buffer overflow (>${HANDSHAKE_BUFFER_LIMIT} bytes); closing`)
        );
        replyFatal(SocksReply.GENERAL_FAILURE);
        return false;
      }
      buffer = Buffer.concat([buffer, chunk]);
      return true;
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

      if (!appendToHandshakeBuffer(chunk)) return;

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

          // Reject unknown ATYP up-front with the spec-mandated reply code.
          // `socksRequestFrameLength` returns `4` for unknown ATYP so we
          // don't wait forever for bytes that will never come; without
          // this guard, `parseSocksRequest` would throw and the outer catch
          // would emit a generic GENERAL_FAILURE — but RFC 1928 requires
          // ADDRESS_TYPE_NOT_SUPPORTED (0x08) for this case.
          const atyp = buffer.readUInt8(3);
          if (
            atyp !== SocksAddressType.IPv4 &&
            atyp !== SocksAddressType.DOMAIN &&
            atyp !== SocksAddressType.IPv6
          ) {
            replyFatal(SocksReply.ADDRESS_TYPE_NOT_SUPPORTED);
            return;
          }

          const request = parseSocksRequest(buffer.subarray(0, total));
          buffer = buffer.subarray(total);

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

          const ctx: SocksConnectionContext = auth ? { request, auth } : { request };

          if (request.command === SocksCommand.CONNECT) {
            // Set the phase before kicking off the async open: the .then
            // handler runs in a microtask, but a future refactor that
            // happened to do work synchronously could see a stale phase
            // if we assigned it after the call.
            phase = ConnectionPhase.Connecting;
            this.handleConnect(socket, ctx, closeAll, {
              setRelayingPhase: (cs) => {
                circuitStream = cs;
                phase = ConnectionPhase.Relaying;
              },
              isClosed: () => phase === ConnectionPhase.Closed,
              flushPipelined: (stream) => {
                if (buffer.length === 0) return;
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
              },
            });
            return;
          }

          if (
            request.command === SocksCommand.RESOLVE ||
            request.command === SocksCommand.RESOLVE_PTR
          ) {
            phase = ConnectionPhase.Connecting;
            this.handleResolve(socket, ctx, {
              isClosed: () => phase === ConnectionPhase.Closed,
            });
            return;
          }

          replyFatal(SocksReply.COMMAND_NOT_SUPPORTED);
          return;
        }
      } catch (err) {
        this.emit('connectionError', err as Error);
        // `replyFatal` already half-closes via `socket.end()`; calling
        // `closeAll()` here would race the FIN with `socket.destroy()`
        // and the failure reply could be lost on the wire. The
        // socket's `'close'` listener will trigger `closeAll()` after
        // the FIN flushes.
        replyFatal(SocksReply.GENERAL_FAILURE);
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

  /**
   * Run an anonymous DNS lookup over the connection's circuit. Used by both
   * the SOCKS RESOLVE and RESOLVE_PTR command paths — pulled out so tests
   * can stub the DNS step without going through the full Tor BEGIN cell.
   */
  protected async runResolveForConnection(
    ctx: SocksConnectionContext,
    query: string
  ): Promise<RelayResolvedRecord[]> {
    const circuit = await this.circuitProvider(ctx);
    return circuit.resolve(query);
  }

  private handleConnect(
    socket: net.Socket,
    ctx: SocksConnectionContext,
    closeAll: (err?: Error) => void,
    hooks: {
      setRelayingPhase: (cs: CircuitStream) => void;
      isClosed: () => boolean;
      flushPipelined: (stream: CircuitStream) => void;
    }
  ): void {
    const { request, auth } = ctx;
    const destination = formatTorDestination(request.destinationAddress, request.destinationPort);
    this.emit('connect', { destination, request, auth, socket });

    // Pause the socket while we open a Tor stream so any extra bytes the
    // client speculatively sends don't show up as 'data' events on a
    // half-built circuit stream.
    socket.pause();
    this.openStreamForConnection(ctx, destination)
      .then((stream) => {
        if (hooks.isClosed()) {
          stream.destroy();
          return;
        }
        // Write the SUCCEEDED reply BEFORE attaching the 'data' listener
        // so the exit can't push application bytes (banner-protocol-style:
        // SMTP/IRC/etc. servers speak first) into the socket ahead of the
        // SOCKS reply. JS is single-threaded so no event-loop tick can
        // interleave a DATA cell between this write and `setupRelay()`,
        // and bytes inside `socket.write()` are delivered in submission
        // order regardless of when the actual flush happens.
        if (!socket.destroyed) {
          socket.write(buildSocksReply(SocksReply.SUCCEEDED));
        }
        this.setupRelay(socket, stream, closeAll);
        hooks.setRelayingPhase(stream);
        if (!socket.destroyed) socket.resume();
        hooks.flushPipelined(stream);
      })
      .catch((err: Error) => {
        this.emit('connectionError', err);
        // Write the error reply with `socket.end()` and let the OS-level
        // FIN flush the bytes to the client. Calling `closeAll()` here
        // would race the FIN with `socket.destroy()` and lose the reply
        // bytes; the natural `'close'` event still triggers cleanup.
        if (!socket.destroyed) {
          socket.write(buildSocksReply(socksReplyForOpenError(err)));
          socket.end();
        }
      });
  }

  private handleResolve(
    socket: net.Socket,
    ctx: SocksConnectionContext,
    hooks: {
      isClosed: () => boolean;
    }
  ): void {
    const { request } = ctx;
    let query: string;
    try {
      query = buildResolveQuery(request);
    } catch (err) {
      this.emit('connectionError', err as Error);
      // Same FIN-vs-RST consideration as in `handleConnect`'s catch path.
      if (!socket.destroyed) {
        socket.write(buildSocksReply(SocksReply.ADDRESS_TYPE_NOT_SUPPORTED));
        socket.end();
      }
      return;
    }
    this.emit('resolve', { request, query, socket });

    this.runResolveForConnection(ctx, query)
      .then((records) => {
        if (hooks.isClosed() || socket.destroyed) return;
        const reply = buildResolveReply(request.command, records);
        socket.write(reply);
        socket.end();
        // RESOLVE / RESOLVE_PTR are one-shot: after the reply, the socket's
        // natural `'close'` listener calls `cleanupConnection()`, which
        // removes it from `this.connections`. Don't preemptively mark phase
        // Closed here — that would short-circuit `cleanupConnection()` and
        // leak the socket in the connections set.
      })
      .catch((err: Error) => {
        this.emit('connectionError', err);
        if (!socket.destroyed) {
          socket.write(buildSocksReply(socksReplyForOpenError(err)));
          socket.end();
        }
      });
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

/**
 * Convert a SOCKS RESOLVE / RESOLVE_PTR request into the query string that
 * RELAY_RESOLVE expects. For forward queries the hostname goes through as
 * is; for reverse queries the IP is rewritten into its `in-addr.arpa` /
 * `ip6.arpa` form (same as c-tor and Arti).
 */
export function buildResolveQuery(request: SocksRequest): string {
  if (request.command === SocksCommand.RESOLVE) {
    if (request.addressType === SocksAddressType.DOMAIN) {
      return request.destinationAddress;
    }
    // Forward-resolving an IP literal is well-defined (it's a no-op): just
    // pass it through as a name, the exit will return whatever it has.
    return request.destinationAddress;
  }
  if (request.command === SocksCommand.RESOLVE_PTR) {
    if (request.addressType === SocksAddressType.IPv4) {
      return ipv4ToInAddrArpa(request.destinationAddress);
    }
    if (request.addressType === SocksAddressType.IPv6) {
      return ipv6ToIp6Arpa(request.destinationAddress);
    }
    throw new Error('RESOLVE_PTR requires an IPv4 or IPv6 address');
  }
  throw new Error(`Not a RESOLVE/RESOLVE_PTR command: ${request.command}`);
}

/**
 * Build the SOCKS5 reply for a RESOLVE / RESOLVE_PTR command from the list
 * of records the exit returned. Picks the first usable record:
 *
 *  - RESOLVE: first IPv4 (or IPv6 if no v4 was returned)
 *  - RESOLVE_PTR: first Hostname record
 *
 * If only error records are present, returns `HOST_UNREACHABLE` for
 * permanent errors (Type 0xF1) and `TTL_EXPIRED` for transient ones
 * (Type 0xF0); empty record lists become `HOST_UNREACHABLE`.
 */
export function buildResolveReply(command: SocksCommand, records: RelayResolvedRecord[]): Buffer {
  if (command === SocksCommand.RESOLVE) {
    const v4 = records.find((r) => r.type === RelayResolvedType.IPv4 && r.value.length === 4);
    if (v4) {
      return buildSocksTypedReply(
        SocksReply.SUCCEEDED,
        { type: SocksAddressType.IPv4, address: formatResolvedIPv4(v4.value) },
        0
      );
    }
    const v6 = records.find((r) => r.type === RelayResolvedType.IPv6 && r.value.length === 16);
    if (v6) {
      return buildSocksTypedReply(
        SocksReply.SUCCEEDED,
        { type: SocksAddressType.IPv6, address: formatResolvedIPv6(v6.value) },
        0
      );
    }
    return buildSocksReply(replyForResolveErrorRecords(records));
  }
  if (command === SocksCommand.RESOLVE_PTR) {
    const host = records.find((r) => r.type === RelayResolvedType.Hostname);
    if (host) {
      return buildSocksTypedReply(
        SocksReply.SUCCEEDED,
        { type: SocksAddressType.DOMAIN, address: host.value.toString('ascii') },
        0
      );
    }
    return buildSocksReply(replyForResolveErrorRecords(records));
  }
  throw new Error(`Not a RESOLVE/RESOLVE_PTR command: ${command}`);
}

function replyForResolveErrorRecords(records: RelayResolvedRecord[]): SocksReply {
  if (records.some((r) => r.type === RelayResolvedType.ErrorPermanent)) {
    return SocksReply.HOST_UNREACHABLE;
  }
  if (records.some((r) => r.type === RelayResolvedType.ErrorTransient)) {
    return SocksReply.TTL_EXPIRED;
  }
  return SocksReply.HOST_UNREACHABLE;
}

/** Construct and start a {@link SocksProxyServer} in one call. */
export async function createSocksProxy(options: SocksServerOptions): Promise<SocksProxyServer> {
  const server = new SocksProxyServer(options);
  await server.start();
  return server;
}
