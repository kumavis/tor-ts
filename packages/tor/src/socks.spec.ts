/**
 * Unit tests for the SOCKS5 protocol pieces in socks.ts.
 *
 * Server-level wiring (Tor circuit + socket relay) is exercised by the
 * Chutney integration test in scripts/chutney-socks-ci.ts; here we test
 * the pure parser/serializer entry points and the SocksProxyServer with
 * an in-memory fake circuit so the tests stay hermetic.
 */

import test from 'ava';
import net from 'node:net';
import { EventEmitter, once } from 'node:events';
import { ReadableStream, WritableStream } from 'node:stream/web';

import {
  SOCKS_VERSION,
  SOCKS_USERPASS_VERSION,
  SocksAuthMethod,
  SocksCommand,
  SocksAddressType,
  SocksReply,
  SocksProxyServer,
  buildResolveQuery,
  buildResolveReply,
  buildSocksGreetingResponse,
  buildSocksReply,
  buildSocksTypedReply,
  buildSocksUserPassResponse,
  createSocksProxy,
  formatTorDestination,
  parseSocksGreeting,
  parseSocksRequest,
  parseSocksUserPass,
  socksGreetingFrameLength,
  socksReplyForOpenError,
  socksReplyForRelayEndReason,
  socksRequestFrameLength,
  socksUserPassFrameLength,
  type SocksConnectionContext,
} from './socks.ts';
import { Circuit, CircuitStream } from './circuit.ts';
import {
  RelayEndError,
  RelayEndReasons,
  RelayResolvedType,
  type RelayResolvedRecord,
} from './relay-cell.ts';

// =============================================================================
// Constants
// =============================================================================

test('SOCKS_VERSION is 5', (t) => {
  t.is(SOCKS_VERSION, 0x05);
});

test('SocksAuthMethod values', (t) => {
  t.is(SocksAuthMethod.NO_AUTH, 0x00);
  t.is(SocksAuthMethod.GSSAPI, 0x01);
  t.is(SocksAuthMethod.USERNAME_PASSWORD, 0x02);
  t.is(SocksAuthMethod.NO_ACCEPTABLE, 0xff);
});

test('SocksCommand values', (t) => {
  t.is(SocksCommand.CONNECT, 0x01);
  t.is(SocksCommand.BIND, 0x02);
  t.is(SocksCommand.UDP_ASSOCIATE, 0x03);
});

test('SocksAddressType values', (t) => {
  t.is(SocksAddressType.IPv4, 0x01);
  t.is(SocksAddressType.DOMAIN, 0x03);
  t.is(SocksAddressType.IPv6, 0x04);
});

test('SocksReply values', (t) => {
  t.is(SocksReply.SUCCEEDED, 0x00);
  t.is(SocksReply.GENERAL_FAILURE, 0x01);
  t.is(SocksReply.CONNECTION_NOT_ALLOWED, 0x02);
  t.is(SocksReply.NETWORK_UNREACHABLE, 0x03);
  t.is(SocksReply.HOST_UNREACHABLE, 0x04);
  t.is(SocksReply.CONNECTION_REFUSED, 0x05);
  t.is(SocksReply.TTL_EXPIRED, 0x06);
  t.is(SocksReply.COMMAND_NOT_SUPPORTED, 0x07);
  t.is(SocksReply.ADDRESS_TYPE_NOT_SUPPORTED, 0x08);
});

// =============================================================================
// parseSocksGreeting / buildSocksGreetingResponse
// =============================================================================

test('parseSocksGreeting: NO_AUTH only', (t) => {
  const data = Buffer.from([0x05, 0x01, 0x00]);
  const result = parseSocksGreeting(data);
  t.is(result.version, 5);
  t.deepEqual(result.methods, [SocksAuthMethod.NO_AUTH]);
});

test('parseSocksGreeting: multiple methods', (t) => {
  const data = Buffer.from([0x05, 0x03, 0x00, 0x01, 0x02]);
  const result = parseSocksGreeting(data);
  t.is(result.version, 5);
  t.deepEqual(result.methods, [
    SocksAuthMethod.NO_AUTH,
    SocksAuthMethod.GSSAPI,
    SocksAuthMethod.USERNAME_PASSWORD,
  ]);
});

test('parseSocksGreeting: throws on too short data', (t) => {
  t.throws(() => parseSocksGreeting(Buffer.from([0x05])), {
    message: 'SOCKS greeting too short',
  });
});

test('parseSocksGreeting: throws on unsupported version', (t) => {
  t.throws(() => parseSocksGreeting(Buffer.from([0x04, 0x01, 0x00])), {
    message: 'Unsupported SOCKS version: 4',
  });
});

test('parseSocksGreeting: throws on truncated methods', (t) => {
  t.throws(() => parseSocksGreeting(Buffer.from([0x05, 0x03, 0x00])), {
    message: 'SOCKS greeting truncated',
  });
});

test('socksGreetingFrameLength: returns undefined for partial frame', (t) => {
  t.is(socksGreetingFrameLength(Buffer.from([0x05])), undefined);
  t.is(socksGreetingFrameLength(Buffer.from([0x05, 0x03, 0x00])), undefined);
});

test('socksGreetingFrameLength: returns total bytes when complete', (t) => {
  t.is(socksGreetingFrameLength(Buffer.from([0x05, 0x01, 0x00])), 3);
  t.is(socksGreetingFrameLength(Buffer.from([0x05, 0x02, 0x00, 0x02])), 4);
});

test('buildSocksGreetingResponse: NO_AUTH', (t) => {
  t.deepEqual(buildSocksGreetingResponse(SocksAuthMethod.NO_AUTH), Buffer.from([0x05, 0x00]));
});

test('buildSocksGreetingResponse: NO_ACCEPTABLE', (t) => {
  t.deepEqual(buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE), Buffer.from([0x05, 0xff]));
});

// =============================================================================
// parseSocksRequest / socksRequestFrameLength
// =============================================================================

test('parseSocksRequest: CONNECT to IPv4', (t) => {
  const data = Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
  const r = parseSocksRequest(data);
  t.is(r.version, 5);
  t.is(r.command, SocksCommand.CONNECT);
  t.is(r.addressType, SocksAddressType.IPv4);
  t.is(r.destinationAddress, '127.0.0.1');
  t.is(r.destinationPort, 80);
});

test('parseSocksRequest: CONNECT to domain', (t) => {
  const domain = 'example.com';
  const data = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, domain.length]),
    Buffer.from(domain, 'ascii'),
    Buffer.from([0x01, 0xbb]),
  ]);
  const r = parseSocksRequest(data);
  t.is(r.command, SocksCommand.CONNECT);
  t.is(r.addressType, SocksAddressType.DOMAIN);
  t.is(r.destinationAddress, 'example.com');
  t.is(r.destinationPort, 443);
});

test('parseSocksRequest: CONNECT to IPv6 ::1', (t) => {
  const ipv6 = Buffer.alloc(16);
  ipv6[15] = 1;
  const data = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x04]),
    ipv6,
    Buffer.from([0x1f, 0x90]),
  ]);
  const r = parseSocksRequest(data);
  t.is(r.addressType, SocksAddressType.IPv6);
  t.is(r.destinationAddress, '0:0:0:0:0:0:0:1');
  t.is(r.destinationPort, 8080);
});

test('parseSocksRequest: BIND command', (t) => {
  const data = Buffer.from([0x05, 0x02, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50]);
  const r = parseSocksRequest(data);
  t.is(r.command, SocksCommand.BIND);
  t.is(r.destinationAddress, '192.168.1.1');
});

test('parseSocksRequest: throws on too short', (t) => {
  t.throws(() => parseSocksRequest(Buffer.from([0x05, 0x01, 0x00])), {
    message: 'SOCKS request too short',
  });
});

test('parseSocksRequest: throws on unsupported version', (t) => {
  t.throws(
    () => parseSocksRequest(Buffer.from([0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])),
    { message: 'Unsupported SOCKS version: 4' }
  );
});

test('parseSocksRequest: throws on non-zero reserved byte (RFC 1928 RSV)', (t) => {
  // Same as the IPv4 happy path but with byte 2 = 0x42 instead of 0x00.
  // Per RFC 1928 RSV must be 0x00; accepting non-zero would mask malformed
  // requests and make traffic-shape mismatches harder to debug.
  t.throws(
    () => parseSocksRequest(Buffer.from([0x05, 0x01, 0x42, 0x01, 127, 0, 0, 1, 0x00, 0x50])),
    { message: /Invalid SOCKS reserved byte: 66/ }
  );
});

test('parseSocksRequest: throws on truncated IPv4', (t) => {
  t.throws(() => parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1])), {
    message: 'SOCKS request too short for IPv4',
  });
});

test('parseSocksRequest: throws on truncated domain', (t) => {
  t.throws(
    () =>
      parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x03, 11, 0x65, 0x78, 0x61, 0x6d, 0x70])),
    { message: 'SOCKS request too short for domain' }
  );
});

test('parseSocksRequest: throws on truncated IPv6', (t) => {
  t.throws(
    () => parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
    { message: 'SOCKS request too short for IPv6' }
  );
});

test('parseSocksRequest: throws on unsupported address type', (t) => {
  t.throws(
    () => parseSocksRequest(Buffer.from([0x05, 0x01, 0x00, 0x05, 127, 0, 0, 1, 0x00, 0x50])),
    { message: 'Unsupported address type: 5' }
  );
});

test('socksRequestFrameLength: IPv4 needs 10 bytes', (t) => {
  const partial = Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00]);
  const full = Buffer.concat([partial, Buffer.from([0x50])]);
  t.is(socksRequestFrameLength(partial), undefined);
  t.is(socksRequestFrameLength(full), 10);
});

test('socksRequestFrameLength: domain needs len + 7 bytes', (t) => {
  const data = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, 11]),
    Buffer.from('example.com', 'ascii'),
    Buffer.from([0x01, 0xbb]),
  ]);
  t.is(socksRequestFrameLength(data), 18);
  t.is(socksRequestFrameLength(data.subarray(0, 10)), undefined);
});

test('socksRequestFrameLength: IPv6 needs 22 bytes', (t) => {
  const buf = Buffer.alloc(22);
  buf[0] = 0x05;
  buf[1] = 0x01;
  buf[3] = 0x04;
  t.is(socksRequestFrameLength(buf), 22);
  t.is(socksRequestFrameLength(buf.subarray(0, 21)), undefined);
});

test('socksRequestFrameLength: returns header length for unknown ATYP', (t) => {
  // ATYP=0x05 is unsupported; we still return 4 so the caller stops waiting.
  t.is(socksRequestFrameLength(Buffer.from([0x05, 0x01, 0x00, 0x05, 0xff, 0xff])), 4);
});

// =============================================================================
// buildSocksReply
// =============================================================================

test('buildSocksReply: SUCCEEDED with default 0.0.0.0:0', (t) => {
  t.deepEqual(
    buildSocksReply(SocksReply.SUCCEEDED),
    Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00])
  );
});

test('buildSocksReply: GENERAL_FAILURE', (t) => {
  t.deepEqual(
    buildSocksReply(SocksReply.GENERAL_FAILURE),
    Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00])
  );
});

test('buildSocksReply: custom bound address + port', (t) => {
  t.deepEqual(
    buildSocksReply(SocksReply.SUCCEEDED, '192.168.1.1', 8080),
    Buffer.from([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x1f, 0x90])
  );
});

test('buildSocksReply: invalid address falls back to 0.0.0.0 (port preserved)', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, 'invalid', 80);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]));
});

test('buildSocksReply: high port encodes big-endian', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '0.0.0.0', 65535);
  t.is(reply[8], 0xff);
  t.is(reply[9], 0xff);
});

test('buildSocksReply: out-of-range octets fall back to 0.0.0.0 (no mod-256 truncation)', (t) => {
  // 999 mod 256 = 231 — the old code would have silently emitted that;
  // the validating version falls back cleanly to 0.0.0.0.
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '999.0.0.1', 80);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]));
});

test('buildSocksReply: negative octets fall back to 0.0.0.0', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '-1.0.0.0', 80);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]));
});

test('buildSocksReply: empty string falls back to 0.0.0.0', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '', 80);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]));
});

// =============================================================================
// formatTorDestination + socksReplyForOpenError
// =============================================================================

test('formatTorDestination: IPv4 stays bare', (t) => {
  t.is(formatTorDestination('127.0.0.1', 80), '127.0.0.1:80');
});

test('formatTorDestination: domain stays bare', (t) => {
  t.is(formatTorDestination('example.com', 443), 'example.com:443');
});

test('formatTorDestination: IPv6 gets bracketed', (t) => {
  t.is(formatTorDestination('::1', 8080), '[::1]:8080');
});

test('socksReplyForOpenError: maps net error codes', (t) => {
  t.is(socksReplyForOpenError({ code: 'ENETUNREACH' }), SocksReply.NETWORK_UNREACHABLE);
  t.is(socksReplyForOpenError({ code: 'ECONNREFUSED' }), SocksReply.CONNECTION_REFUSED);
  t.is(socksReplyForOpenError({ code: 'EHOSTUNREACH' }), SocksReply.HOST_UNREACHABLE);
  t.is(socksReplyForOpenError({ code: 'ETIMEDOUT' }), SocksReply.TTL_EXPIRED);
  t.is(socksReplyForOpenError({}), SocksReply.HOST_UNREACHABLE);
  t.is(socksReplyForOpenError(null), SocksReply.HOST_UNREACHABLE);
});

test('socksReplyForOpenError: prefers RelayEndError reason over Node code', (t) => {
  // RelayEndError takes precedence — the Tor-side reason is more specific.
  const err = new RelayEndError(RelayEndReasons.REASON_EXITPOLICY, 'aabb');
  t.is(socksReplyForOpenError(err), SocksReply.CONNECTION_NOT_ALLOWED);
});

// =============================================================================
// socksReplyForRelayEndReason — mirrors c-tor's stream_end_reason_to_socks5_response
// =============================================================================

test('socksReplyForRelayEndReason: known reasons map per c-tor', (t) => {
  t.is(
    socksReplyForRelayEndReason(RelayEndReasons.REASON_RESOLVEFAILED),
    SocksReply.HOST_UNREACHABLE
  );
  t.is(
    socksReplyForRelayEndReason(RelayEndReasons.REASON_CONNECTREFUSED),
    SocksReply.CONNECTION_REFUSED
  );
  t.is(
    socksReplyForRelayEndReason(RelayEndReasons.REASON_EXITPOLICY),
    SocksReply.CONNECTION_NOT_ALLOWED
  );
  t.is(socksReplyForRelayEndReason(RelayEndReasons.REASON_TIMEOUT), SocksReply.TTL_EXPIRED);
  t.is(socksReplyForRelayEndReason(RelayEndReasons.REASON_NOROUTE), SocksReply.NETWORK_UNREACHABLE);
});

test('socksReplyForRelayEndReason: catch-all reasons fall through to GENERAL_FAILURE', (t) => {
  for (const reason of [
    RelayEndReasons.REASON_MISC,
    RelayEndReasons.REASON_DESTROY,
    RelayEndReasons.REASON_DONE,
    RelayEndReasons.REASON_HIBERNATING,
    RelayEndReasons.REASON_INTERNAL,
    RelayEndReasons.REASON_RESOURCELIMIT,
    RelayEndReasons.REASON_CONNRESET,
    RelayEndReasons.REASON_TORPROTOCOL,
    RelayEndReasons.REASON_NOTDIRECTORY,
  ]) {
    t.is(socksReplyForRelayEndReason(reason), SocksReply.GENERAL_FAILURE, `reason=${reason}`);
  }
});

test('socksReplyForRelayEndReason: unknown reason falls through to GENERAL_FAILURE', (t) => {
  t.is(socksReplyForRelayEndReason(99), SocksReply.GENERAL_FAILURE);
});

// =============================================================================
// RFC 1929 user/pass sub-negotiation
// =============================================================================

test('parseSocksUserPass: simple username + password', (t) => {
  const data = Buffer.concat([
    Buffer.from([SOCKS_USERPASS_VERSION, 4]),
    Buffer.from('user', 'ascii'),
    Buffer.from([4]),
    Buffer.from('pass', 'ascii'),
  ]);
  const auth = parseSocksUserPass(data);
  t.is(auth.username.toString('ascii'), 'user');
  t.is(auth.password.toString('ascii'), 'pass');
});

test('parseSocksUserPass: empty username + password (Tor isolation pattern)', (t) => {
  const data = Buffer.from([SOCKS_USERPASS_VERSION, 0, 0]);
  const auth = parseSocksUserPass(data);
  t.is(auth.username.length, 0);
  t.is(auth.password.length, 0);
});

test('parseSocksUserPass: throws on too short', (t) => {
  t.throws(() => parseSocksUserPass(Buffer.from([SOCKS_USERPASS_VERSION])), {
    message: 'SOCKS user/pass too short',
  });
});

test('parseSocksUserPass: throws on unsupported version', (t) => {
  // 0x05 is the SOCKS5 version, not the user/pass sub-negotiation version.
  t.throws(() => parseSocksUserPass(Buffer.from([0x05, 0x00, 0x00])), {
    message: 'Unsupported SOCKS user/pass version: 5',
  });
});

test('parseSocksUserPass: throws on truncated PASSWD', (t) => {
  // ULEN=4 'user', PLEN=4 'pa' (truncated)
  const data = Buffer.concat([
    Buffer.from([SOCKS_USERPASS_VERSION, 4]),
    Buffer.from('user', 'ascii'),
    Buffer.from([4]),
    Buffer.from('pa', 'ascii'),
  ]);
  t.throws(() => parseSocksUserPass(data), { message: /SOCKS user\/pass truncated/ });
});

test('parseSocksUserPass: throws when PLEN byte itself is missing', (t) => {
  // VER + ULEN=4 + 'user', no PLEN.
  const data = Buffer.concat([
    Buffer.from([SOCKS_USERPASS_VERSION, 4]),
    Buffer.from('user', 'ascii'),
  ]);
  t.throws(() => parseSocksUserPass(data), { message: /SOCKS user\/pass truncated/ });
});

test('socksUserPassFrameLength: complete frame returns total length', (t) => {
  // VER + ULEN=4 + 'user' + PLEN=4 + 'pass' = 11 bytes
  const data = Buffer.concat([
    Buffer.from([SOCKS_USERPASS_VERSION, 4]),
    Buffer.from('user', 'ascii'),
    Buffer.from([4]),
    Buffer.from('pass', 'ascii'),
  ]);
  t.is(socksUserPassFrameLength(data), 11);
});

test('socksUserPassFrameLength: returns undefined for partial frames', (t) => {
  t.is(socksUserPassFrameLength(Buffer.from([SOCKS_USERPASS_VERSION])), undefined);
  // VER + ULEN=4 but no UNAME yet
  t.is(socksUserPassFrameLength(Buffer.from([SOCKS_USERPASS_VERSION, 4])), undefined);
  // Missing PLEN byte
  t.is(
    socksUserPassFrameLength(
      Buffer.concat([Buffer.from([SOCKS_USERPASS_VERSION, 4]), Buffer.from('user', 'ascii')])
    ),
    undefined
  );
  // Missing PASSWD bytes
  t.is(
    socksUserPassFrameLength(
      Buffer.concat([
        Buffer.from([SOCKS_USERPASS_VERSION, 4]),
        Buffer.from('user', 'ascii'),
        Buffer.from([4]),
        Buffer.from('pa', 'ascii'),
      ])
    ),
    undefined
  );
});

test('buildSocksUserPassResponse: defaults to status=0 (success)', (t) => {
  t.deepEqual(buildSocksUserPassResponse(), Buffer.from([SOCKS_USERPASS_VERSION, 0]));
});

test('buildSocksUserPassResponse: explicit non-zero status is preserved', (t) => {
  t.deepEqual(buildSocksUserPassResponse(0xff), Buffer.from([SOCKS_USERPASS_VERSION, 0xff]));
});

// =============================================================================
// SocksProxyServer wiring with a fake circuit
// =============================================================================
//
// We build a CircuitStream-shaped object and feed it into a Circuit-shaped
// fake. The actual Circuit class wires `.write` from inside `createStream`,
// which is not what we want for tests; here we substitute a stream that
// loops bytes back to the SOCKS client so we can verify the relay.

class LoopbackStream extends EventEmitter {
  streamId = 1;
  destination: string;
  destroyed = false;
  // The Circuit class fills these in for real streams; the SOCKS server
  // never touches them so a no-op is fine.
  source = new ReadableStream({ start() {} });
  sink = new WritableStream({ write() {} });
  constructor(destination: string) {
    super();
    this.destination = destination;
    this.on('error', () => {
      // suppress unhandled
    });
  }
  // Echo the chunk straight back to the client side via 'data'.
  write = async (data: Buffer): Promise<void> => {
    if (this.destroyed) throw new Error('stream destroyed');
    this.emit('data', data);
  };
  close(): void {
    this.destroy();
  }
  destroy(err?: Error): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (err) this.emit('error', err);
    this.emit('end');
  }
}

class FakeCircuit {
  public lastDestination: string | undefined;
  public openCalls = 0;
  public openMode: 'echo' | 'reject' = 'echo';
  public rejectError: Error = new Error('open failed');

  // Resolve hooks
  public lastResolveQuery: string | undefined;
  public resolveCalls = 0;
  public resolveMode: 'records' | 'reject' = 'records';
  public resolveResult: RelayResolvedRecord[] = [];
  public resolveRejectError: Error = new Error('resolve failed');

  async open(destination: string): Promise<CircuitStream> {
    this.openCalls += 1;
    this.lastDestination = destination;
    if (this.openMode === 'reject') {
      throw this.rejectError;
    }
    return new LoopbackStream(destination) as unknown as CircuitStream;
  }

  async resolve(query: string): Promise<RelayResolvedRecord[]> {
    this.resolveCalls += 1;
    this.lastResolveQuery = query;
    if (this.resolveMode === 'reject') {
      throw this.resolveRejectError;
    }
    return this.resolveResult;
  }
}

const fakeCircuitAsCircuit = (fake: FakeCircuit): Circuit => fake as unknown as Circuit;

function chooseEphemeralPort(): number {
  // Bind to port 0 to get a free port, then close. There's a small race
  // where another process could grab the port between close and our
  // re-bind, but in CI that's vanishingly rare and the test is short.
  return 0;
}

async function startServer(fake: FakeCircuit): Promise<{
  server: SocksProxyServer;
  port: number;
}> {
  const server = new SocksProxyServer({
    circuit: fakeCircuitAsCircuit(fake),
    port: chooseEphemeralPort(),
    host: '127.0.0.1',
  });
  await server.start();
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('server address not bound');
  }
  return { server, port: addr.port };
}

/**
 * Pull bytes off `socket` into a single buffered queue. Each `read(n)`
 * waits until at least `n` bytes are available across all chunks ever
 * received, then returns the next `n` bytes and leaves the rest queued
 * for the next reader. This is more reliable than installing a fresh
 * 'data' listener per call (which can race with chunk arrival).
 */
function makeByteReader(socket: net.Socket): {
  read: (n: number, label: string) => Promise<Buffer>;
} {
  let queued = Buffer.alloc(0);
  let waiter:
    | { n: number; label: string; resolve: (b: Buffer) => void; reject: (e: Error) => void }
    | undefined;

  const tryDeliver = () => {
    if (!waiter) return;
    if (queued.length >= waiter.n) {
      const out = queued.subarray(0, waiter.n);
      queued = queued.subarray(waiter.n);
      const w = waiter;
      waiter = undefined;
      w.resolve(out);
    }
  };

  socket.on('data', (chunk: Buffer) => {
    queued = Buffer.concat([queued, chunk]);
    tryDeliver();
  });
  socket.on('close', () => {
    if (waiter) {
      const w = waiter;
      waiter = undefined;
      w.reject(new Error(`${w.label}: socket closed before ${w.n} bytes available`));
    }
  });
  socket.on('error', (err) => {
    if (waiter) {
      const w = waiter;
      waiter = undefined;
      w.reject(new Error(`${w.label}: ${err.message}`));
    }
  });

  return {
    read: (n: number, label: string) =>
      new Promise<Buffer>((resolve, reject) => {
        if (waiter) {
          reject(new Error('makeByteReader: only one read at a time'));
          return;
        }
        waiter = { n, label, resolve, reject };
        tryDeliver();
      }),
  };
}

test('SocksProxyServer: createSocksProxy starts listening', async (t) => {
  const fake = new FakeCircuit();
  const server = await createSocksProxy({
    circuit: fakeCircuitAsCircuit(fake),
    port: 0,
    host: '127.0.0.1',
  });
  const addr = server.address();
  t.truthy(addr);
  t.true(typeof addr === 'object' && addr !== null && (addr as net.AddressInfo).port > 0);
  await server.stop();
});

test('SocksProxyServer: full handshake + relay echoes data', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    // 1. Greeting (NO_AUTH only) → expect 0x05 0x00
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    const greetResp = await reader.read(2, 'greeting');
    t.deepEqual(greetResp, Buffer.from([SOCKS_VERSION, SocksAuthMethod.NO_AUTH]));

    // 2. CONNECT to example.com:80 (domain ATYP)
    const domain = 'example.com';
    const req = Buffer.concat([
      Buffer.from([
        SOCKS_VERSION,
        SocksCommand.CONNECT,
        0x00,
        SocksAddressType.DOMAIN,
        domain.length,
      ]),
      Buffer.from(domain, 'ascii'),
      Buffer.from([0x00, 0x50]),
    ]);
    socket.write(req);
    const reply = await reader.read(10, 'connect');
    t.is(reply[0], SOCKS_VERSION);
    t.is(reply[1], SocksReply.SUCCEEDED);
    t.is(fake.openCalls, 1);
    t.is(fake.lastDestination, 'example.com:80');

    // 3. Send some payload bytes; the loopback stream echoes them back.
    const payload = Buffer.from('GET / HTTP/1.0\r\n\r\n');
    socket.write(payload);
    const echo = await reader.read(payload.length, 'echo');
    t.deepEqual(echo, payload);

    socket.destroy();
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: rejects unsupported auth methods', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    // GSSAPI only — we never advertise it.
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.GSSAPI]));
    const resp = await reader.read(2, 'greeting');
    t.deepEqual(resp, Buffer.from([SOCKS_VERSION, SocksAuthMethod.NO_ACCEPTABLE]));
    await once(socket, 'close');
    t.is(fake.openCalls, 0);
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: rejects non-CONNECT commands with COMMAND_NOT_SUPPORTED', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');

    // BIND command
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.BIND, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[0], SOCKS_VERSION);
    t.is(reply[1], SocksReply.COMMAND_NOT_SUPPORTED);
    t.is(fake.openCalls, 0);
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: unknown ATYP → ADDRESS_TYPE_NOT_SUPPORTED (per RFC 1928)', async (t) => {
  // socksRequestFrameLength returns 4 for unknown ATYP so we don't wait
  // forever for bytes that will never come — but the spec-correct REP is
  // 0x08 (ADDRESS_TYPE_NOT_SUPPORTED), not the generic 0x01 the parser
  // would otherwise raise.
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');

    // CONNECT with ATYP=0x05 (not a real address type).
    socket.write(Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x05]));
    const reply = await reader.read(10, 'reply');
    t.is(reply[0], SOCKS_VERSION);
    t.is(reply[1], SocksReply.ADDRESS_TYPE_NOT_SUPPORTED);
    t.is(fake.openCalls, 0);
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: failed circuit.open replies HOST_UNREACHABLE', async (t) => {
  const fake = new FakeCircuit();
  fake.openMode = 'reject';
  fake.rejectError = Object.assign(new Error('host unreachable'), { code: 'EHOSTUNREACH' });

  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');

    const req = Buffer.from([
      SOCKS_VERSION,
      SocksCommand.CONNECT,
      0x00,
      0x01,
      127,
      0,
      0,
      1,
      0x00,
      0x50,
    ]);
    socket.write(req);
    const reply = await reader.read(10, 'reply');
    t.is(reply[0], SOCKS_VERSION);
    t.is(reply[1], SocksReply.HOST_UNREACHABLE);
    await once(socket, 'close');
    t.is(fake.openCalls, 1);
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: handles greeting + request arriving in one chunk', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    // Stitch the greeting and CONNECT request into a single TCP write so
    // the server handles them within one 'data' event each.
    const greeting = Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]);
    const request = Buffer.from([
      SOCKS_VERSION,
      SocksCommand.CONNECT,
      0x00,
      SocksAddressType.IPv4,
      127,
      0,
      0,
      1,
      0x1f,
      0x90,
    ]);
    socket.write(Buffer.concat([greeting, request]));

    const greetResp = await reader.read(2, 'greeting');
    t.deepEqual(greetResp, Buffer.from([SOCKS_VERSION, SocksAuthMethod.NO_AUTH]));
    const reply = await reader.read(10, 'connect');
    t.is(reply[1], SocksReply.SUCCEEDED);
    t.is(fake.lastDestination, '127.0.0.1:8080');

    socket.destroy();
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: replays bytes pipelined after the request', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');

    // Send the request and a body chunk in a single TCP write. The server
    // is asynchronously opening the circuit when the body bytes arrive,
    // so it must buffer and replay them once the relay is wired up.
    const req = Buffer.from([
      SOCKS_VERSION,
      SocksCommand.CONNECT,
      0x00,
      0x01,
      127,
      0,
      0,
      1,
      0x00,
      0x50,
    ]);
    const body = Buffer.from('hello-pipelined');
    socket.write(Buffer.concat([req, body]));

    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.SUCCEEDED);

    // The loopback stream echoes whatever it receives, so the pipelined
    // body should come back to us verbatim.
    const echo = await reader.read(body.length, 'echo');
    t.deepEqual(echo, body);

    socket.destroy();
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: stop() closes active client sockets', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  const socket = net.connect(port, '127.0.0.1');
  await once(socket, 'connect');
  const reader = makeByteReader(socket);
  socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
  await reader.read(2, 'greeting');

  const closed = once(socket, 'close');
  await server.stop();
  await closed;
  t.pass();
});

test('SocksProxyServer: handshake buffer overflow during greeting → NO_ACCEPTABLE + close', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    socket.on('error', () => {
      // Expected once the server ends — keep the test from crashing on EPIPE.
    });

    const errs: Error[] = [];
    server.on('connectionError', (e: Error) => errs.push(e));

    // Send a single chunk that's well over the 4 KiB handshake buffer cap.
    // Byte 0 (= 0x05) is a valid SOCKS5 version, byte 1 (= 0xff) promises
    // 255 methods, so the greeting frame won't be complete until we've
    // received 257 bytes. Before that point, appending 5 KiB at once
    // pushes the buffer past 4 KiB and the overflow guard fires.
    const blob = Buffer.concat([Buffer.from([SOCKS_VERSION, 0xff]), Buffer.alloc(5000, 0xfe)]);
    socket.write(blob);

    // Drain whatever the server writes, then wait for the close.
    let received = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
    });
    await once(socket, 'close');

    // We're still in the Greeting phase when the overflow trips, so the
    // phase-aware replyFatal sends a 2-byte method-selection reply with
    // NO_ACCEPTABLE — NOT a 10-byte CONNECT-shape reply that the client
    // would misparse as method=GSSAPI (0x01). This is the spec-correct
    // wire shape for a fatal failure during the greeting.
    t.is(received[0], SOCKS_VERSION);
    t.is(received[1], SocksAuthMethod.NO_ACCEPTABLE);
    t.is(received.length, 2, 'greeting-phase failure should be exactly 2 bytes');
    t.true(
      errs.some((e) => /handshake buffer overflow/.test(e.message)),
      `expected at least one connectionError matching /handshake buffer overflow/, got: ${errs.map((e) => e.message).join(', ')}`
    );
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: malformed user/pass after USERNAME_PASSWORD greeting → 2-byte failure status', async (t) => {
  // Drives the Auth-phase branch of the phase-aware replyFatal: a parse
  // error during the RFC 1929 sub-negotiation should produce a 2-byte
  // status reply (VER=0x01, STATUS=0xff), NOT a 10-byte CONNECT-shape
  // reply that the client would misparse.
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    socket.on('error', () => {
      // Expected after server.end().
    });
    const reader = makeByteReader(socket);

    // Greeting: only USERNAME_PASSWORD → server picks USERNAME_PASSWORD
    // and we move to the Auth phase.
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.USERNAME_PASSWORD]));
    const greetReply = await reader.read(2, 'greeting');
    t.deepEqual(greetReply, Buffer.from([SOCKS_VERSION, SocksAuthMethod.USERNAME_PASSWORD]));

    // Send a malformed user/pass sub-negotiation: VER=0x05 (wrong — should
    // be 0x01 per RFC 1929). socksUserPassFrameLength sees ULEN=0, PLEN=0
    // so the frame "completes" at 3 bytes, then parseSocksUserPass throws
    // on the bad VER, the outer catch fires, and replyFatal must produce
    // a 2-byte failure status (not a 10-byte CONNECT-shape reply).
    socket.write(Buffer.from([0x05, 0x00, 0x00]));
    const failReply = await reader.read(2, 'auth-fail');
    t.is(failReply[0], SOCKS_USERPASS_VERSION, 'VER byte is the user/pass version (0x01)');
    t.is(failReply[1], 0xff, 'STATUS byte is non-zero (failure)');
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

// =============================================================================
// USERNAME_PASSWORD support
// =============================================================================

test('SocksProxyServer: prefers NO_AUTH when both methods are offered', async (t) => {
  const fake = new FakeCircuit();
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    socket.write(
      Buffer.from([SOCKS_VERSION, 0x02, SocksAuthMethod.NO_AUTH, SocksAuthMethod.USERNAME_PASSWORD])
    );
    const resp = await reader.read(2, 'greeting');
    // c-tor's `socks_prefer_no_auth` mirrors this: pick NO_AUTH.
    t.deepEqual(resp, Buffer.from([SOCKS_VERSION, SocksAuthMethod.NO_AUTH]));
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: falls back to USERNAME_PASSWORD when NO_AUTH absent', async (t) => {
  const fake = new FakeCircuit();
  let connectCtx: { auth?: { username: Buffer; password: Buffer } } | undefined;
  const server = new SocksProxyServer({
    circuit: fakeCircuitAsCircuit(fake),
    port: 0,
    host: '127.0.0.1',
  });
  server.on(
    'connect',
    (evt: { auth?: { username: Buffer; password: Buffer } }) => (connectCtx = evt)
  );
  await server.start();
  try {
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('not bound');
    const socket = net.connect(addr.port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    // Greeting: only USERNAME_PASSWORD
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.USERNAME_PASSWORD]));
    const greetResp = await reader.read(2, 'greeting');
    t.deepEqual(greetResp, Buffer.from([SOCKS_VERSION, SocksAuthMethod.USERNAME_PASSWORD]));

    // RFC 1929 sub-negotiation
    const username = 'tor-iso-key';
    const password = 's3cret';
    socket.write(
      Buffer.concat([
        Buffer.from([SOCKS_USERPASS_VERSION, username.length]),
        Buffer.from(username, 'ascii'),
        Buffer.from([password.length]),
        Buffer.from(password, 'ascii'),
      ])
    );
    const authResp = await reader.read(2, 'auth');
    // Tor always succeeds (status=0).
    t.deepEqual(authResp, Buffer.from([SOCKS_USERPASS_VERSION, 0]));

    // CONNECT
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'connect');
    t.is(reply[1], SocksReply.SUCCEEDED);

    // The auth payload was surfaced on 'connect' — that's the isolation hook.
    t.is(connectCtx?.auth?.username.toString('ascii'), username);
    t.is(connectCtx?.auth?.password.toString('ascii'), password);

    socket.destroy();
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: empty user/pass (Tor Browser isolation idiom) succeeds', async (t) => {
  const fake = new FakeCircuit();
  const server = new SocksProxyServer({
    circuit: fakeCircuitAsCircuit(fake),
    port: 0,
    host: '127.0.0.1',
  });
  await server.start();
  try {
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('not bound');
    const socket = net.connect(addr.port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);

    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.USERNAME_PASSWORD]));
    await reader.read(2, 'greeting');
    socket.write(Buffer.from([SOCKS_USERPASS_VERSION, 0, 0]));
    const authResp = await reader.read(2, 'auth');
    t.deepEqual(authResp, Buffer.from([SOCKS_USERPASS_VERSION, 0]));

    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'connect');
    t.is(reply[1], SocksReply.SUCCEEDED);
    socket.destroy();
  } finally {
    await server.stop();
  }
});

// =============================================================================
// circuitFactory option (per-connection isolation)
// =============================================================================

test('SocksServerOptions: rejects both circuit and circuitFactory', (t) => {
  const fake = new FakeCircuit();
  t.throws(
    () =>
      new SocksProxyServer({
        circuit: fakeCircuitAsCircuit(fake),
        circuitFactory: async () => fakeCircuitAsCircuit(fake),
      }),
    { message: /pass either `circuit` or `circuitFactory`, not both/ }
  );
});

test('SocksServerOptions: requires one of circuit / circuitFactory', (t) => {
  t.throws(() => new SocksProxyServer({}), {
    message: /either `circuit` or `circuitFactory` is required/,
  });
});

test('SocksProxyServer: circuitFactory receives request + auth + is invoked per connection', async (t) => {
  const fakes = [new FakeCircuit(), new FakeCircuit()];
  let calls = 0;
  const seen: SocksConnectionContext[] = [];
  const server = new SocksProxyServer({
    circuitFactory: async (ctx) => {
      seen.push(ctx);
      const fake = fakes[calls % fakes.length]!;
      calls += 1;
      return fakeCircuitAsCircuit(fake);
    },
    port: 0,
    host: '127.0.0.1',
  });
  await server.start();
  try {
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('not bound');

    // Two clients with distinct USERNAME_PASSWORD isolation keys.
    const driveOne = async (user: string, host: string) => {
      const socket = net.connect(addr.port, '127.0.0.1');
      await once(socket, 'connect');
      const reader = makeByteReader(socket);
      socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.USERNAME_PASSWORD]));
      await reader.read(2, 'greeting');
      socket.write(
        Buffer.concat([
          Buffer.from([SOCKS_USERPASS_VERSION, user.length]),
          Buffer.from(user, 'ascii'),
          Buffer.from([0]),
        ])
      );
      await reader.read(2, 'auth');
      const hostBytes = Buffer.from(host, 'ascii');
      socket.write(
        Buffer.concat([
          Buffer.from([
            SOCKS_VERSION,
            SocksCommand.CONNECT,
            0x00,
            SocksAddressType.DOMAIN,
            hostBytes.length,
          ]),
          hostBytes,
          Buffer.from([0x00, 0x50]),
        ])
      );
      const reply = await reader.read(10, 'connect');
      t.is(reply[1], SocksReply.SUCCEEDED);
      socket.destroy();
    };

    await driveOne('iso-key-A', 'a.example');
    await driveOne('iso-key-B', 'b.example');

    t.is(calls, 2);
    t.is(seen.length, 2);
    t.is(seen[0]!.auth!.username.toString('ascii'), 'iso-key-A');
    t.is(seen[0]!.request.destinationAddress, 'a.example');
    t.is(seen[1]!.auth!.username.toString('ascii'), 'iso-key-B');
    t.is(seen[1]!.request.destinationAddress, 'b.example');
    t.is(fakes[0]!.openCalls, 1);
    t.is(fakes[1]!.openCalls, 1);
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: circuitFactory rejection replies HOST_UNREACHABLE', async (t) => {
  const server = new SocksProxyServer({
    circuitFactory: async () => {
      throw Object.assign(new Error('factory failed'), { code: 'EHOSTUNREACH' });
    },
    port: 0,
    host: '127.0.0.1',
  });
  await server.start();
  try {
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('not bound');
    const socket = net.connect(addr.port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.HOST_UNREACHABLE);
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

// =============================================================================
// circuit.open() failure surfaces RelayEndError-derived REP
// =============================================================================

test('SocksProxyServer: RELAY_END EXITPOLICY surfaces as CONNECTION_NOT_ALLOWED', async (t) => {
  const fake = new FakeCircuit();
  fake.openMode = 'reject';
  fake.rejectError = new RelayEndError(RelayEndReasons.REASON_EXITPOLICY, '04');
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.CONNECTION_NOT_ALLOWED);
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: RELAY_END TIMEOUT surfaces as TTL_EXPIRED', async (t) => {
  const fake = new FakeCircuit();
  fake.openMode = 'reject';
  fake.rejectError = new RelayEndError(RelayEndReasons.REASON_TIMEOUT, '07');
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.TTL_EXPIRED);
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

// =============================================================================
// SocksCommand: RESOLVE / RESOLVE_PTR enum values
// =============================================================================

test('SocksCommand: RESOLVE/RESOLVE_PTR are Tor proposal-100 extensions', (t) => {
  t.is(SocksCommand.RESOLVE, 0xf0);
  t.is(SocksCommand.RESOLVE_PTR, 0xf1);
});

// =============================================================================
// buildSocksTypedReply
// =============================================================================

test('buildSocksTypedReply: IPv4 bound address', (t) => {
  const out = buildSocksTypedReply(
    SocksReply.SUCCEEDED,
    { type: SocksAddressType.IPv4, address: '93.184.216.34' },
    0
  );
  t.deepEqual(out, Buffer.from([0x05, 0x00, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x00]));
});

test('buildSocksTypedReply: IPv6 bound address', (t) => {
  const out = buildSocksTypedReply(
    SocksReply.SUCCEEDED,
    { type: SocksAddressType.IPv6, address: '::1' },
    0
  );
  t.is(out.length, 4 + 16 + 2);
  t.is(out[0], 0x05);
  t.is(out[1], 0x00);
  t.is(out[3], SocksAddressType.IPv6);
  // ::1 → 15 zero bytes followed by 0x01
  t.is(out[19], 0x01);
});

test('buildSocksTypedReply: DOMAIN bound address (length-prefixed)', (t) => {
  const out = buildSocksTypedReply(
    SocksReply.SUCCEEDED,
    { type: SocksAddressType.DOMAIN, address: 'host.example.com' },
    0
  );
  t.is(out[0], 0x05);
  t.is(out[3], SocksAddressType.DOMAIN);
  t.is(out[4], 'host.example.com'.length);
  t.is(out.subarray(5, 5 + 16).toString('ascii'), 'host.example.com');
});

test('buildSocksTypedReply: rejects oversized domain (>255)', (t) => {
  const tooBig = 'a'.repeat(256);
  t.throws(
    () =>
      buildSocksTypedReply(
        SocksReply.SUCCEEDED,
        { type: SocksAddressType.DOMAIN, address: tooBig },
        0
      ),
    { message: /Domain address too long/ }
  );
});

test('buildSocksTypedReply: rejects malformed IPv4', (t) => {
  t.throws(
    () =>
      buildSocksTypedReply(
        SocksReply.SUCCEEDED,
        { type: SocksAddressType.IPv4, address: '256.0.0.0' },
        0
      ),
    { message: /Not a valid IPv4/ }
  );
});

// =============================================================================
// buildResolveQuery / buildResolveReply
// =============================================================================

test('buildResolveQuery: forward DOMAIN passes through verbatim', (t) => {
  const req = {
    version: 5,
    command: SocksCommand.RESOLVE,
    addressType: SocksAddressType.DOMAIN,
    destinationAddress: 'example.com',
    destinationPort: 0,
  };
  t.is(buildResolveQuery(req), 'example.com');
});

test('buildResolveQuery: PTR IPv4 → in-addr.arpa', (t) => {
  const req = {
    version: 5,
    command: SocksCommand.RESOLVE_PTR,
    addressType: SocksAddressType.IPv4,
    destinationAddress: '8.8.8.8',
    destinationPort: 0,
  };
  t.is(buildResolveQuery(req), '8.8.8.8.in-addr.arpa');
});

test('buildResolveQuery: PTR IPv6 → ip6.arpa', (t) => {
  const req = {
    version: 5,
    command: SocksCommand.RESOLVE_PTR,
    addressType: SocksAddressType.IPv6,
    destinationAddress: '0:0:0:0:0:0:0:1',
    destinationPort: 0,
  };
  t.true(buildResolveQuery(req).endsWith('.ip6.arpa'));
});

test('buildResolveQuery: rejects PTR with non-IP address', (t) => {
  t.throws(
    () =>
      buildResolveQuery({
        version: 5,
        command: SocksCommand.RESOLVE_PTR,
        addressType: SocksAddressType.DOMAIN,
        destinationAddress: 'example.com',
        destinationPort: 0,
      }),
    { message: /requires an IPv4 or IPv6/ }
  );
});

test('buildResolveQuery: rejects non-RESOLVE command', (t) => {
  t.throws(
    () =>
      buildResolveQuery({
        version: 5,
        command: SocksCommand.CONNECT,
        addressType: SocksAddressType.IPv4,
        destinationAddress: '1.2.3.4',
        destinationPort: 80,
      }),
    { message: /Not a RESOLVE/ }
  );
});

test('buildResolveReply: RESOLVE picks the first IPv4 record', (t) => {
  const records: RelayResolvedRecord[] = [
    { type: RelayResolvedType.IPv4, value: Buffer.from([93, 184, 216, 34]), ttl: 60 },
    { type: RelayResolvedType.IPv6, value: Buffer.alloc(16), ttl: 60 },
  ];
  const out = buildResolveReply(SocksCommand.RESOLVE, records);
  t.is(out[0], 0x05);
  t.is(out[1], SocksReply.SUCCEEDED);
  t.is(out[3], SocksAddressType.IPv4);
  t.deepEqual(out.subarray(4, 8), Buffer.from([93, 184, 216, 34]));
});

test('buildResolveReply: RESOLVE falls back to IPv6 when no IPv4 present', (t) => {
  const v6 = Buffer.alloc(16);
  v6[15] = 1; // ::1
  const records: RelayResolvedRecord[] = [{ type: RelayResolvedType.IPv6, value: v6, ttl: 60 }];
  const out = buildResolveReply(SocksCommand.RESOLVE, records);
  t.is(out[1], SocksReply.SUCCEEDED);
  t.is(out[3], SocksAddressType.IPv6);
  t.is(out[4 + 15], 1);
});

test('buildResolveReply: RESOLVE with only permanent error → HOST_UNREACHABLE', (t) => {
  const records: RelayResolvedRecord[] = [
    { type: RelayResolvedType.ErrorPermanent, value: Buffer.from('nope'), ttl: 0 },
  ];
  const out = buildResolveReply(SocksCommand.RESOLVE, records);
  t.is(out[1], SocksReply.HOST_UNREACHABLE);
});

test('buildResolveReply: RESOLVE with transient error → TTL_EXPIRED', (t) => {
  const records: RelayResolvedRecord[] = [
    { type: RelayResolvedType.ErrorTransient, value: Buffer.from('temp'), ttl: 0 },
  ];
  const out = buildResolveReply(SocksCommand.RESOLVE, records);
  t.is(out[1], SocksReply.TTL_EXPIRED);
});

test('buildResolveReply: RESOLVE with no records → HOST_UNREACHABLE', (t) => {
  const out = buildResolveReply(SocksCommand.RESOLVE, []);
  t.is(out[1], SocksReply.HOST_UNREACHABLE);
});

test('buildResolveReply: RESOLVE_PTR picks first Hostname record', (t) => {
  const name = 'host.example.com';
  const records: RelayResolvedRecord[] = [
    { type: RelayResolvedType.Hostname, value: Buffer.from(name, 'ascii'), ttl: 60 },
  ];
  const out = buildResolveReply(SocksCommand.RESOLVE_PTR, records);
  t.is(out[1], SocksReply.SUCCEEDED);
  t.is(out[3], SocksAddressType.DOMAIN);
  t.is(out[4], name.length);
  t.is(out.subarray(5, 5 + name.length).toString('ascii'), name);
});

test('buildResolveReply: RESOLVE_PTR with only error records → HOST_UNREACHABLE', (t) => {
  const records: RelayResolvedRecord[] = [
    { type: RelayResolvedType.ErrorPermanent, value: Buffer.from('nope'), ttl: 0 },
  ];
  const out = buildResolveReply(SocksCommand.RESOLVE_PTR, records);
  t.is(out[1], SocksReply.HOST_UNREACHABLE);
});

// =============================================================================
// SocksProxyServer: RESOLVE / RESOLVE_PTR end-to-end
// =============================================================================

async function driveResolveClient(
  port: number,
  command: SocksCommand,
  atyp: SocksAddressType,
  addrBytes: Buffer
): Promise<Buffer> {
  const socket = net.connect(port, '127.0.0.1');
  await once(socket, 'connect');
  const reader = makeByteReader(socket);
  socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
  await reader.read(2, 'greeting');

  const reqHead = Buffer.from([SOCKS_VERSION, command, 0x00, atyp]);
  const port0 = Buffer.from([0x00, 0x00]);
  const req =
    atyp === SocksAddressType.DOMAIN
      ? Buffer.concat([reqHead, Buffer.from([addrBytes.length]), addrBytes, port0])
      : Buffer.concat([reqHead, addrBytes, port0]);
  socket.write(req);

  // Read enough bytes to learn the bound-ATYP, then read the appropriate body length.
  const head = await reader.read(4, 'reply-head');
  switch (head[3]) {
    case SocksAddressType.IPv4: {
      const body = await reader.read(4 + 2, 'reply-body-v4');
      socket.destroy();
      return Buffer.concat([head, body]);
    }
    case SocksAddressType.IPv6: {
      const body = await reader.read(16 + 2, 'reply-body-v6');
      socket.destroy();
      return Buffer.concat([head, body]);
    }
    case SocksAddressType.DOMAIN: {
      const len = await reader.read(1, 'domain-len');
      const dom = await reader.read(len[0]!, 'domain-value');
      const portBytes = await reader.read(2, 'port');
      socket.destroy();
      return Buffer.concat([head, len, dom, portBytes]);
    }
    default:
      socket.destroy();
      return head;
  }
}

test('SocksProxyServer: RESOLVE forward returns IPv4 reply', async (t) => {
  const fake = new FakeCircuit();
  fake.resolveResult = [
    { type: RelayResolvedType.IPv4, value: Buffer.from([93, 184, 216, 34]), ttl: 300 },
  ];
  const { server, port } = await startServer(fake);
  try {
    const reply = await driveResolveClient(
      port,
      SocksCommand.RESOLVE,
      SocksAddressType.DOMAIN,
      Buffer.from('example.com', 'ascii')
    );
    t.is(reply[1], SocksReply.SUCCEEDED);
    t.is(reply[3], SocksAddressType.IPv4);
    t.deepEqual(reply.subarray(4, 8), Buffer.from([93, 184, 216, 34]));
    t.is(fake.resolveCalls, 1);
    t.is(fake.lastResolveQuery, 'example.com');
    t.is(fake.openCalls, 0); // RESOLVE never opens a TCP-style stream
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: RESOLVE_PTR returns DOMAIN reply with hostname', async (t) => {
  const fake = new FakeCircuit();
  fake.resolveResult = [
    { type: RelayResolvedType.Hostname, value: Buffer.from('dns.google', 'ascii'), ttl: 60 },
  ];
  const { server, port } = await startServer(fake);
  try {
    const reply = await driveResolveClient(
      port,
      SocksCommand.RESOLVE_PTR,
      SocksAddressType.IPv4,
      Buffer.from([8, 8, 8, 8])
    );
    t.is(reply[1], SocksReply.SUCCEEDED);
    t.is(reply[3], SocksAddressType.DOMAIN);
    t.is(reply[4], 'dns.google'.length);
    t.is(reply.subarray(5, 5 + 'dns.google'.length).toString('ascii'), 'dns.google');
    t.is(fake.lastResolveQuery, '8.8.8.8.in-addr.arpa');
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: RESOLVE with REASON_RESOLVEFAILED → HOST_UNREACHABLE', async (t) => {
  const fake = new FakeCircuit();
  fake.resolveMode = 'reject';
  fake.resolveRejectError = new RelayEndError(RelayEndReasons.REASON_RESOLVEFAILED, '02');
  const { server, port } = await startServer(fake);
  try {
    const reply = await driveResolveClient(
      port,
      SocksCommand.RESOLVE,
      SocksAddressType.DOMAIN,
      Buffer.from('nope.invalid', 'ascii')
    );
    t.is(reply[1], SocksReply.HOST_UNREACHABLE);
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: RESOLVE with empty record list → HOST_UNREACHABLE', async (t) => {
  const fake = new FakeCircuit();
  fake.resolveResult = [];
  const { server, port } = await startServer(fake);
  try {
    const reply = await driveResolveClient(
      port,
      SocksCommand.RESOLVE,
      SocksAddressType.DOMAIN,
      Buffer.from('example.com', 'ascii')
    );
    t.is(reply[1], SocksReply.HOST_UNREACHABLE);
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: RESOLVE leaves no socket behind in `connections` after close', async (t) => {
  // Regression test for the markClosed leak: previously, the success path
  // set `phase = Closed` *before* the socket's natural `'close'` listener
  // ran `cleanupConnection()`. cleanupConnection early-returns on
  // `phase === Closed`, so the socket was never removed from
  // `this.connections` and the set grew without bound across resolves.
  const fake = new FakeCircuit();
  fake.resolveResult = [
    { type: RelayResolvedType.IPv4, value: Buffer.from([1, 2, 3, 4]), ttl: 60 },
  ];
  const server = new SocksProxyServer({
    circuit: fakeCircuitAsCircuit(fake),
    port: 0,
    host: '127.0.0.1',
  });
  await server.start();
  try {
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('not bound');
    const connections = (server as unknown as { connections: Set<net.Socket> }).connections;

    // Drive 5 sequential RESOLVE connections. For each one, capture the
    // server-side socket via the underlying `net.Server`'s 'connection'
    // event and wait for it to actually close before moving on — that
    // guarantees the server-side `'close'` listener has run
    // `cleanupConnection()` and removed the socket from the set.
    const internalServer = (server as unknown as { server: net.Server }).server;
    for (let i = 0; i < 5; i++) {
      const serverSocketP = once(internalServer, 'connection') as Promise<[net.Socket]>;
      const replyP = driveResolveClient(
        addr.port,
        SocksCommand.RESOLVE,
        SocksAddressType.DOMAIN,
        Buffer.from(`host${i}.example`, 'ascii')
      );
      const [serverSocket] = await serverSocketP;
      const reply = await replyP;
      t.is(reply[1], SocksReply.SUCCEEDED, `resolve ${i} succeeded`);
      // Wait for the server-side socket's 'close' so cleanupConnection has run.
      if (!serverSocket.destroyed) await once(serverSocket, 'close');
      t.is(connections.size, 0, `connections leaked after resolve ${i}`);
    }

    t.is(fake.resolveCalls, 5);
  } finally {
    await server.stop();
  }
});

// =============================================================================
// Regression: failure replies must reach the client via graceful FIN, not
// be raced by `socket.destroy()`. Before the closeAll-after-end fix, the
// server emitted the reply but then aborted the socket; clients saw a bare
// 'close' without 'end' and could lose the reply bytes on real networks.
// On the client side, 'end' fires iff our FIN arrives before any RST.
// =============================================================================

test('SocksProxyServer: failed CONNECT reply arrives + socket ends gracefully', async (t) => {
  const fake = new FakeCircuit();
  fake.openMode = 'reject';
  fake.rejectError = Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    const seenEnd = once(socket, 'end');

    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');
    socket.write(
      Buffer.from([SOCKS_VERSION, SocksCommand.CONNECT, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.CONNECTION_REFUSED);
    // The server must have called socket.end() (not destroy()), so the
    // client sees an FIN-driven 'end' before 'close'.
    await seenEnd;
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});

test('SocksProxyServer: failed RESOLVE reply arrives + socket ends gracefully', async (t) => {
  const fake = new FakeCircuit();
  fake.resolveMode = 'reject';
  fake.resolveRejectError = new RelayEndError(RelayEndReasons.REASON_RESOLVEFAILED, '02');
  const { server, port } = await startServer(fake);
  try {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const reader = makeByteReader(socket);
    const seenEnd = once(socket, 'end');

    socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    await reader.read(2, 'greeting');
    const hostBytes = Buffer.from('nope.invalid', 'ascii');
    socket.write(
      Buffer.concat([
        Buffer.from([
          SOCKS_VERSION,
          SocksCommand.RESOLVE,
          0x00,
          SocksAddressType.DOMAIN,
          hostBytes.length,
        ]),
        hostBytes,
        Buffer.from([0x00, 0x00]),
      ])
    );
    const reply = await reader.read(10, 'reply');
    t.is(reply[1], SocksReply.HOST_UNREACHABLE);
    await seenEnd;
    await once(socket, 'close');
  } finally {
    await server.stop();
  }
});
