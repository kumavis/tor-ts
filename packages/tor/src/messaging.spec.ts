/**
 * Tests for Tor cell messaging serialization and parsing.
 */

import test from 'ava';
import {
  serializeRelayCellPayload,
  parseRelayCellPayload,
  setRelayCellIntegrity,
  checkRelayCellRecognized,
  chunkDataForRelayDataCells,
  addressAndPortToBuffer,
  linkSpecifierToAddressAndPort,
  addressAndPortToLinkSpecifier,
  AddressTypes,
  LinkSpecifierTypes,
  RELAY_PAYLOAD_LEN,
} from './messaging.ts';
import type { CellRelay, LinkSpecifier, AddressAndPort } from './messaging.ts';
import { RelayCell } from './relay-cell.ts';

test('serializeRelayCellPayload: creates 509-byte payload', (t) => {
  const relayCell: CellRelay = {
    relayCommand: RelayCell.DATA,
    streamId: 1,
    data: Buffer.from('test data', 'utf-8'),
  };

  const payload = serializeRelayCellPayload(relayCell);
  t.is(payload.length, 509);
});

test('parseRelayCellPayload: roundtrip', (t) => {
  const original: CellRelay = {
    relayCommand: RelayCell.DATA,
    streamId: 42,
    data: Buffer.from('hello world', 'utf-8'),
  };

  const serialized = serializeRelayCellPayload(original);
  const parsed = parseRelayCellPayload(serialized);

  t.is(parsed.relayCommand, original.relayCommand);
  t.is(parsed.streamId, original.streamId);
  t.deepEqual(parsed.data, original.data);
});

test('parseRelayCellPayload: parses recognized field as zeros', (t) => {
  const relayCell: CellRelay = {
    relayCommand: RelayCell.BEGIN,
    streamId: 1,
    data: Buffer.from('example.com:80\0', 'utf-8'),
  };

  const serialized = serializeRelayCellPayload(relayCell);
  const parsed = parseRelayCellPayload(serialized);

  // Recognized field should be zeros
  t.deepEqual(parsed.recognized, Buffer.alloc(2));
});

test('setRelayCellIntegrity: modifies payload at correct offset', (t) => {
  const relayCell: CellRelay = {
    relayCommand: RelayCell.DATA,
    streamId: 1,
    data: Buffer.from('test', 'utf-8'),
  };

  const payload = serializeRelayCellPayload(relayCell);
  const integrity = Buffer.from([0xde, 0xad, 0xbe, 0xef]);

  setRelayCellIntegrity(payload, integrity);
  const parsed = parseRelayCellPayload(payload);

  t.deepEqual(parsed.integrity, integrity);
});

test('checkRelayCellRecognized: returns true for valid cell with recognized=0', (t) => {
  const relayCell: CellRelay = {
    relayCommand: RelayCell.DATA,
    streamId: 1,
    data: Buffer.from('test', 'utf-8'),
  };

  const payload = serializeRelayCellPayload(relayCell);
  t.true(checkRelayCellRecognized(payload));
});

test('checkRelayCellRecognized: returns false for non-zero recognized', (t) => {
  const relayCell: CellRelay = {
    relayCommand: RelayCell.DATA,
    streamId: 1,
    data: Buffer.from('test', 'utf-8'),
  };

  const payload = serializeRelayCellPayload(relayCell);
  // Modify recognized field at offset 1 (after command byte)
  payload[1] = 0xff;

  t.false(checkRelayCellRecognized(payload));
});

test('checkRelayCellRecognized: returns false for invalid length field', (t) => {
  const payload = Buffer.alloc(509);
  // Set recognized to 0
  payload[1] = 0;
  payload[2] = 0;
  // Set length field to an invalid value (> PAYLOAD_LEN - 11)
  const lengthOffset = 1 + 2 + 2 + 4;
  payload.writeUInt16BE(600, lengthOffset); // 600 > 498

  t.false(checkRelayCellRecognized(payload));
});

test('chunkDataForRelayDataCells: returns single chunk for small data', (t) => {
  const data = Buffer.from('small data', 'utf-8');
  const chunks = chunkDataForRelayDataCells(data);

  t.is(chunks.length, 1);
  t.deepEqual(chunks[0], data);
});

test('chunkDataForRelayDataCells: splits data at RELAY_PAYLOAD_LEN boundary', (t) => {
  // Create data larger than RELAY_PAYLOAD_LEN (498 bytes)
  const data = Buffer.alloc(1000);
  data.fill(0xab);

  const chunks = chunkDataForRelayDataCells(data);

  t.is(chunks.length, 3); // 498 + 498 + 4 = 1000
  t.is(chunks[0]!.length, RELAY_PAYLOAD_LEN);
  t.is(chunks[1]!.length, RELAY_PAYLOAD_LEN);
  t.is(chunks[2]!.length, 1000 - 2 * RELAY_PAYLOAD_LEN);

  // Verify content
  t.deepEqual(Buffer.concat(chunks), data);
});

test('chunkDataForRelayDataCells: returns exact RELAY_PAYLOAD_LEN chunk', (t) => {
  const data = Buffer.alloc(RELAY_PAYLOAD_LEN);
  data.fill(0x42);

  const chunks = chunkDataForRelayDataCells(data);

  t.is(chunks.length, 1);
  t.deepEqual(chunks[0], data);
});

test('addressAndPortToBuffer: serializes IPv4 address', (t) => {
  const address: AddressAndPort = {
    type: AddressTypes.IPv4,
    ip: '192.168.1.1',
    port: 443,
  };

  const buffer = addressAndPortToBuffer(address);

  // 4 bytes for IP + 2 bytes for port
  t.is(buffer.length, 6);
  t.is(buffer[0], 192);
  t.is(buffer[1], 168);
  t.is(buffer[2], 1);
  t.is(buffer[3], 1);
  t.is(buffer.readUInt16BE(4), 443);
});

test('addressAndPortToLinkSpecifier: creates correct link specifier for IPv4', (t) => {
  const address: AddressAndPort = {
    type: AddressTypes.IPv4,
    ip: '10.0.0.1',
    port: 9001,
  };

  const linkSpec = addressAndPortToLinkSpecifier(address);

  t.is(linkSpec.type, LinkSpecifierTypes.TlsOverTcpIPv4);
  t.is(linkSpec.data.length, 6);
});

test('linkSpecifierToAddressAndPort: parses IPv4 link specifier', (t) => {
  const linkSpec: LinkSpecifier = {
    type: LinkSpecifierTypes.TlsOverTcpIPv4,
    data: Buffer.from([127, 0, 0, 1, 0x23, 0x29]), // 127.0.0.1:9001
  };

  const address = linkSpecifierToAddressAndPort(linkSpec);

  t.is(address.type, AddressTypes.IPv4);
  t.is(address.ip, '127.0.0.1');
  t.is(address.port, 9001);
});

test('addressAndPortToLinkSpecifier + linkSpecifierToAddressAndPort: roundtrip', (t) => {
  const original: AddressAndPort = {
    type: AddressTypes.IPv4,
    ip: '203.0.113.45',
    port: 8443,
  };

  const linkSpec = addressAndPortToLinkSpecifier(original);
  const parsed = linkSpecifierToAddressAndPort(linkSpec);

  t.is(parsed.type, original.type);
  t.is(parsed.ip, original.ip);
  t.is(parsed.port, original.port);
});

test('RELAY_PAYLOAD_LEN: is 498 bytes', (t) => {
  // PAYLOAD_LEN (509) - 11 byte header = 498
  t.is(RELAY_PAYLOAD_LEN, 498);
});
