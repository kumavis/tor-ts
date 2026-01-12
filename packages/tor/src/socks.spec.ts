/**
 * Unit tests for SOCKS5 protocol implementation.
 */

import test from 'ava';
import {
  SOCKS_VERSION,
  SocksAuthMethod,
  SocksCommand,
  SocksAddressType,
  SocksReply,
  parseSocksGreeting,
  buildSocksGreetingResponse,
  parseSocksRequest,
  buildSocksReply,
} from './socks.ts';

// =============================================================================
// Constants tests
// =============================================================================

test('SOCKS_VERSION is 5', (t) => {
  t.is(SOCKS_VERSION, 0x05);
});

test('SocksAuthMethod values are correct', (t) => {
  t.is(SocksAuthMethod.NO_AUTH, 0x00);
  t.is(SocksAuthMethod.GSSAPI, 0x01);
  t.is(SocksAuthMethod.USERNAME_PASSWORD, 0x02);
  t.is(SocksAuthMethod.NO_ACCEPTABLE, 0xff);
});

test('SocksCommand values are correct', (t) => {
  t.is(SocksCommand.CONNECT, 0x01);
  t.is(SocksCommand.BIND, 0x02);
  t.is(SocksCommand.UDP_ASSOCIATE, 0x03);
});

test('SocksAddressType values are correct', (t) => {
  t.is(SocksAddressType.IPv4, 0x01);
  t.is(SocksAddressType.DOMAIN, 0x03);
  t.is(SocksAddressType.IPv6, 0x04);
});

test('SocksReply values are correct', (t) => {
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
// parseSocksGreeting tests
// =============================================================================

test('parseSocksGreeting: parses greeting with NO_AUTH', (t) => {
  // VER: 0x05, NMETHODS: 0x01, METHODS: [0x00]
  const data = Buffer.from([0x05, 0x01, 0x00]);
  const result = parseSocksGreeting(data);
  t.is(result.version, 5);
  t.deepEqual(result.methods, [SocksAuthMethod.NO_AUTH]);
});

test('parseSocksGreeting: parses greeting with multiple methods', (t) => {
  // VER: 0x05, NMETHODS: 0x03, METHODS: [0x00, 0x01, 0x02]
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
  const data = Buffer.from([0x05]);
  t.throws(() => parseSocksGreeting(data), { message: 'SOCKS greeting too short' });
});

test('parseSocksGreeting: throws on unsupported version', (t) => {
  const data = Buffer.from([0x04, 0x01, 0x00]);
  t.throws(() => parseSocksGreeting(data), { message: 'Unsupported SOCKS version: 4' });
});

test('parseSocksGreeting: throws on truncated methods', (t) => {
  // VER: 0x05, NMETHODS: 0x03, but only 1 method byte
  const data = Buffer.from([0x05, 0x03, 0x00]);
  t.throws(() => parseSocksGreeting(data), { message: 'SOCKS greeting truncated' });
});

// =============================================================================
// buildSocksGreetingResponse tests
// =============================================================================

test('buildSocksGreetingResponse: builds NO_AUTH response', (t) => {
  const response = buildSocksGreetingResponse(SocksAuthMethod.NO_AUTH);
  t.deepEqual(response, Buffer.from([0x05, 0x00]));
});

test('buildSocksGreetingResponse: builds NO_ACCEPTABLE response', (t) => {
  const response = buildSocksGreetingResponse(SocksAuthMethod.NO_ACCEPTABLE);
  t.deepEqual(response, Buffer.from([0x05, 0xff]));
});

// =============================================================================
// parseSocksRequest tests
// =============================================================================

test('parseSocksRequest: parses CONNECT to IPv4 address', (t) => {
  // VER: 0x05, CMD: CONNECT, RSV: 0x00, ATYP: IPv4,
  // DST.ADDR: 127.0.0.1, DST.PORT: 80 (0x0050)
  const data = Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
  const result = parseSocksRequest(data);
  t.is(result.version, 5);
  t.is(result.command, SocksCommand.CONNECT);
  t.is(result.addressType, SocksAddressType.IPv4);
  t.is(result.destinationAddress, '127.0.0.1');
  t.is(result.destinationPort, 80);
});

test('parseSocksRequest: parses CONNECT to domain', (t) => {
  // VER: 0x05, CMD: CONNECT, RSV: 0x00, ATYP: DOMAIN,
  // DST.ADDR: example.com (11 bytes), DST.PORT: 443 (0x01bb)
  const domain = 'example.com';
  const data = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, domain.length]),
    Buffer.from(domain, 'ascii'),
    Buffer.from([0x01, 0xbb]),
  ]);
  const result = parseSocksRequest(data);
  t.is(result.version, 5);
  t.is(result.command, SocksCommand.CONNECT);
  t.is(result.addressType, SocksAddressType.DOMAIN);
  t.is(result.destinationAddress, 'example.com');
  t.is(result.destinationPort, 443);
});

test('parseSocksRequest: parses CONNECT to IPv6 address', (t) => {
  // VER: 0x05, CMD: CONNECT, RSV: 0x00, ATYP: IPv6,
  // DST.ADDR: ::1 (16 bytes), DST.PORT: 8080 (0x1f90)
  const ipv6Bytes = Buffer.alloc(16);
  ipv6Bytes[15] = 1; // ::1
  const data = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x04]),
    ipv6Bytes,
    Buffer.from([0x1f, 0x90]),
  ]);
  const result = parseSocksRequest(data);
  t.is(result.version, 5);
  t.is(result.command, SocksCommand.CONNECT);
  t.is(result.addressType, SocksAddressType.IPv6);
  t.is(result.destinationAddress, '0:0:0:0:0:0:0:1');
  t.is(result.destinationPort, 8080);
});

test('parseSocksRequest: parses BIND command', (t) => {
  const data = Buffer.from([0x05, 0x02, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50]);
  const result = parseSocksRequest(data);
  t.is(result.command, SocksCommand.BIND);
  t.is(result.destinationAddress, '192.168.1.1');
});

test('parseSocksRequest: throws on too short data', (t) => {
  const data = Buffer.from([0x05, 0x01, 0x00]);
  t.throws(() => parseSocksRequest(data), { message: 'SOCKS request too short' });
});

test('parseSocksRequest: throws on unsupported version', (t) => {
  const data = Buffer.from([0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
  t.throws(() => parseSocksRequest(data), { message: 'Unsupported SOCKS version: 4' });
});

test('parseSocksRequest: throws on too short IPv4 request', (t) => {
  // Missing port bytes
  const data = Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]);
  t.throws(() => parseSocksRequest(data), { message: 'SOCKS request too short for IPv4' });
});

test('parseSocksRequest: throws on too short domain request', (t) => {
  // Domain length says 11 but only 5 bytes provided
  const data = Buffer.from([0x05, 0x01, 0x00, 0x03, 11, 0x65, 0x78, 0x61, 0x6d, 0x70]);
  t.throws(() => parseSocksRequest(data), { message: 'SOCKS request too short for domain' });
});

test('parseSocksRequest: throws on too short IPv6 request', (t) => {
  // Only 10 bytes of IPv6 address
  const data = Buffer.from([0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  t.throws(() => parseSocksRequest(data), { message: 'SOCKS request too short for IPv6' });
});

test('parseSocksRequest: throws on unsupported address type', (t) => {
  // Address type 0x05 is not defined
  const data = Buffer.from([0x05, 0x01, 0x00, 0x05, 127, 0, 0, 1, 0x00, 0x50]);
  t.throws(() => parseSocksRequest(data), { message: 'Unsupported address type: 5' });
});

// =============================================================================
// buildSocksReply tests
// =============================================================================

test('buildSocksReply: builds SUCCEEDED reply', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED);
  // VER: 0x05, REP: 0x00, RSV: 0x00, ATYP: IPv4,
  // BND.ADDR: 0.0.0.0, BND.PORT: 0x0000
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00]));
});

test('buildSocksReply: builds GENERAL_FAILURE reply', (t) => {
  const reply = buildSocksReply(SocksReply.GENERAL_FAILURE);
  t.deepEqual(reply, Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00]));
});

test('buildSocksReply: builds reply with custom bound address', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '192.168.1.1', 8080);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x1f, 0x90]));
});

test('buildSocksReply: falls back to 0.0.0.0 for invalid address', (t) => {
  const reply = buildSocksReply(SocksReply.SUCCEEDED, 'invalid', 80);
  t.deepEqual(reply, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50]));
});

test('buildSocksReply: handles port bytes correctly', (t) => {
  // Port 443 = 0x01bb
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '0.0.0.0', 443);
  t.is(reply[8], 0x01);
  t.is(reply[9], 0xbb);
});

test('buildSocksReply: handles high port numbers', (t) => {
  // Port 65535 = 0xffff
  const reply = buildSocksReply(SocksReply.SUCCEEDED, '0.0.0.0', 65535);
  t.is(reply[8], 0xff);
  t.is(reply[9], 0xff);
});
