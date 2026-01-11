/**
 * Tests for relay selection utilities.
 */

import test from 'ava';
import { filterRelaysByFlags, pickRelayWithFlags } from './util.ts';
import type { MicroDescNodeInfo } from './directory.ts';

function createMockRelay(nickname: string, flags: string[] = []): MicroDescNodeInfo {
  return {
    nickname,
    rsaIdDigest: Buffer.from(nickname.padEnd(20, '0')),
    publication_date: new Date(),
    ip_address: '127.0.0.1',
    onion_router_port: 9001,
    directory_server_port: 9030,
    flags,
    protocols: {},
  };
}

test('filterRelaysByFlags: returns all relays when no flags specified', (t) => {
  const relays = [
    createMockRelay('relay1', ['Fast', 'Stable']),
    createMockRelay('relay2', ['Exit']),
    createMockRelay('relay3', []),
  ];

  const result = filterRelaysByFlags(relays, []);
  t.is(result.length, 3);
});

test('filterRelaysByFlags: filters by single flag', (t) => {
  const relays = [
    createMockRelay('relay1', ['Fast', 'Stable']),
    createMockRelay('relay2', ['Exit', 'Fast']),
    createMockRelay('relay3', ['Guard']),
  ];

  const result = filterRelaysByFlags(relays, ['Fast']);
  t.is(result.length, 2);
  t.true(result.some((r) => r.nickname === 'relay1'));
  t.true(result.some((r) => r.nickname === 'relay2'));
});

test('filterRelaysByFlags: filters by multiple flags (all must match)', (t) => {
  const relays = [
    createMockRelay('relay1', ['Fast', 'Stable', 'Exit']),
    createMockRelay('relay2', ['Exit', 'Fast']),
    createMockRelay('relay3', ['Exit', 'Stable']),
  ];

  const result = filterRelaysByFlags(relays, ['Exit', 'Fast']);
  t.is(result.length, 2);
  t.true(result.some((r) => r.nickname === 'relay1'));
  t.true(result.some((r) => r.nickname === 'relay2'));
});

test('filterRelaysByFlags: respects ignore list by reference', (t) => {
  const relay1 = createMockRelay('relay1', ['Fast']);
  const relay2 = createMockRelay('relay2', ['Fast']);
  const relay3 = createMockRelay('relay3', ['Fast']);

  const result = filterRelaysByFlags([relay1, relay2, relay3], ['Fast'], [relay2]);
  t.is(result.length, 2);
  t.true(result.some((r) => r.nickname === 'relay1'));
  t.true(result.some((r) => r.nickname === 'relay3'));
  t.false(result.some((r) => r.nickname === 'relay2'));
});

test('filterRelaysByFlags: respects ignore list by rsaIdDigest', (t) => {
  const relay1 = createMockRelay('relay1', ['Fast']);
  const relay2 = createMockRelay('relay2', ['Fast']);
  const relay2Clone = createMockRelay('relay2', ['Fast']); // Same rsaIdDigest

  const result = filterRelaysByFlags([relay1, relay2], ['Fast'], [relay2Clone]);
  t.is(result.length, 1);
  t.is(result[0]!.nickname, 'relay1');
});

test('filterRelaysByFlags: returns empty when no matches', (t) => {
  const relays = [createMockRelay('relay1', ['Fast']), createMockRelay('relay2', ['Stable'])];

  const result = filterRelaysByFlags(relays, ['Exit']);
  t.is(result.length, 0);
});

test('filterRelaysByFlags: handles relays with undefined flags', (t) => {
  const relay: MicroDescNodeInfo = {
    nickname: 'relay1',
    rsaIdDigest: Buffer.from('relay1'.padEnd(20, '0')),
    publication_date: new Date(),
    ip_address: '127.0.0.1',
    onion_router_port: 9001,
    directory_server_port: 9030,
    protocols: {},
    // flags is undefined
  };

  const result = filterRelaysByFlags([relay], []);
  t.is(result.length, 1);

  const resultWithFlags = filterRelaysByFlags([relay], ['Fast']);
  t.is(resultWithFlags.length, 0);
});

test('pickRelayWithFlags: returns a matching relay', (t) => {
  const relays = [
    createMockRelay('relay1', ['Fast', 'Exit']),
    createMockRelay('relay2', ['Guard']),
  ];

  const picked = pickRelayWithFlags(relays, ['Exit'], []);
  t.is(picked.nickname, 'relay1');
});

test('pickRelayWithFlags: throws when no matches', (t) => {
  const relays = [createMockRelay('relay1', ['Fast']), createMockRelay('relay2', ['Stable'])];

  t.throws(() => pickRelayWithFlags(relays, ['Exit'], []), {
    message: /Failed to find any matching relays/,
  });
});

test('pickRelayWithFlags: respects ignore list', (t) => {
  const relay1 = createMockRelay('relay1', ['Exit']);
  const relay2 = createMockRelay('relay2', ['Exit']);

  // Run multiple times to ensure we never get the ignored relay
  for (let i = 0; i < 20; i++) {
    const picked = pickRelayWithFlags([relay1, relay2], ['Exit'], [relay1]);
    t.is(picked.nickname, 'relay2');
  }
});

test('pickRelayWithFlags: picks from available relays randomly', (t) => {
  const relays = [];
  for (let i = 0; i < 100; i++) {
    relays.push(createMockRelay(`relay${i}`, ['Fast']));
  }

  // Pick multiple times and verify we get different results (probabilistic)
  const picked = new Set<string>();
  for (let i = 0; i < 50; i++) {
    const relay = pickRelayWithFlags(relays, ['Fast'], []);
    picked.add(relay.nickname);
  }

  // With 100 relays and 50 picks, we should get at least a few different ones
  t.true(picked.size > 1, 'Expected multiple different relays to be picked');
});
