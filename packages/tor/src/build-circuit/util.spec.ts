/**
 * Tests for relay selection utilities.
 */

import test from 'ava';
import {
  filterRelaysByFlags,
  pickRelayWithFlags,
  filterExitsByPolicy,
  computeRelayWeights,
  pickRelayWeighted,
  getBandwidthWeightMultiplier,
} from './util.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { parseExitPolicySummary } from '../exit-policy.ts';

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

// Tests for exit policy filtering

function createMockRelayWithPolicy(
  nickname: string,
  flags: string[],
  policyLine?: string,
  bandwidth?: number
): MicroDescNodeInfo {
  const relay: MicroDescNodeInfo = {
    nickname,
    rsaIdDigest: Buffer.from(nickname.padEnd(20, '0')),
    publication_date: new Date(),
    ip_address: '127.0.0.1',
    onion_router_port: 9001,
    directory_server_port: 9030,
    flags,
    protocols: {},
  };
  if (policyLine) {
    const policy = parseExitPolicySummary(policyLine);
    if (policy) relay.exitPolicy = policy;
  }
  if (bandwidth !== undefined) {
    relay.bandwidthStats = { Bandwidth: bandwidth };
  }
  return relay;
}

test('filterExitsByPolicy: filters exits by accept policy', (t) => {
  const relays = [
    createMockRelayWithPolicy('exit1', ['Exit'], 'p accept 80,443'),
    createMockRelayWithPolicy('exit2', ['Exit'], 'p accept 80'),
    createMockRelayWithPolicy('exit3', ['Exit'], 'p accept 443'),
  ];

  // Port 80 only
  const result80 = filterExitsByPolicy(relays, [80]);
  t.is(result80.length, 2);
  t.true(result80.some((r) => r.nickname === 'exit1'));
  t.true(result80.some((r) => r.nickname === 'exit2'));

  // Port 443 only
  const result443 = filterExitsByPolicy(relays, [443]);
  t.is(result443.length, 2);
  t.true(result443.some((r) => r.nickname === 'exit1'));
  t.true(result443.some((r) => r.nickname === 'exit3'));

  // Both ports required
  const resultBoth = filterExitsByPolicy(relays, [80, 443]);
  t.is(resultBoth.length, 1);
  t.is(resultBoth[0]!.nickname, 'exit1');
});

test('filterExitsByPolicy: filters exits by reject policy', (t) => {
  const relays = [
    createMockRelayWithPolicy('exit1', ['Exit'], 'p reject 25,445'),
    createMockRelayWithPolicy('exit2', ['Exit'], 'p reject 80'),
    createMockRelayWithPolicy('exit3', ['Exit'], 'p reject 1-65535'),
  ];

  const result = filterExitsByPolicy(relays, [80, 443]);
  t.is(result.length, 1);
  t.is(result[0]!.nickname, 'exit1');
});

test('filterExitsByPolicy: includes relays without policy info', (t) => {
  const relays = [
    createMockRelayWithPolicy('exit1', ['Exit'], 'p accept 80,443'),
    createMockRelayWithPolicy('exit2', ['Exit'], undefined), // No policy
  ];

  const result = filterExitsByPolicy(relays, [80]);
  t.is(result.length, 2); // Both included - no policy = permissive
});

test('filterExitsByPolicy: empty target ports excludes reject-all', (t) => {
  const relays = [
    createMockRelayWithPolicy('exit1', ['Exit'], 'p accept 80'),
    createMockRelayWithPolicy('exit2', ['Exit'], 'p reject 1-65535'),
  ];

  const result = filterExitsByPolicy(relays, []);
  t.is(result.length, 1);
  t.is(result[0]!.nickname, 'exit1');
});

// Tests for bandwidth-weighted selection

test('computeRelayWeights: computes weights based on bandwidth', (t) => {
  const relays = [
    createMockRelayWithPolicy('relay1', ['Exit'], undefined, 1000),
    createMockRelayWithPolicy('relay2', ['Exit'], undefined, 2000),
    createMockRelayWithPolicy('relay3', ['Exit'], undefined, 3000),
  ];

  const bandwidthWeights = { Wee: 10000 }; // Full weight for exits
  const weights = computeRelayWeights(relays, 'exit', bandwidthWeights);

  t.is(weights.length, 3);
  t.is(weights[0], 1000);
  t.is(weights[1], 2000);
  t.is(weights[2], 3000);
});

test('computeRelayWeights: applies position-specific weight multipliers', (t) => {
  const relay = createMockRelayWithPolicy('relay1', ['Guard', 'Exit'], undefined, 1000);

  const bandwidthWeights = {
    Wgd: 5000, // Guard+Exit in guard position = 0.5
    Wmd: 3000, // Guard+Exit in middle position = 0.3
    Wed: 8000, // Guard+Exit in exit position = 0.8
  };

  t.is(getBandwidthWeightMultiplier(relay, 'guard', bandwidthWeights), 0.5);
  t.is(getBandwidthWeightMultiplier(relay, 'middle', bandwidthWeights), 0.3);
  t.is(getBandwidthWeightMultiplier(relay, 'exit', bandwidthWeights), 0.8);
});

test('pickRelayWeighted: selects based on weights', (t) => {
  const relays = [
    createMockRelayWithPolicy('heavy', ['Exit'], undefined, 9000),
    createMockRelayWithPolicy('light', ['Exit'], undefined, 1000),
  ];

  const weights = [9000, 1000];

  // With random = 0.1, should select first relay (9000/10000 = 0.9 threshold)
  const picked1 = pickRelayWeighted(relays, weights, 0.1);
  t.is(picked1.nickname, 'heavy');

  // With random = 0.95, should select second relay (past 9000/10000 threshold)
  const picked2 = pickRelayWeighted(relays, weights, 0.95);
  t.is(picked2.nickname, 'light');
});

test('pickRelayWeighted: handles zero weights', (t) => {
  const relays = [
    createMockRelayWithPolicy('relay1', ['Exit'], undefined),
    createMockRelayWithPolicy('relay2', ['Exit'], undefined),
  ];

  const weights = [0, 0];

  // Should fall back to uniform random
  const picked = pickRelayWeighted(relays, weights, 0.5);
  t.truthy(picked); // Just verify it doesn't crash
});

test('pickRelayWeighted: throws on empty relay list', (t) => {
  t.throws(() => pickRelayWeighted([], []), {
    message: /No relays to pick from/,
  });
});

test('pickRelayWeighted: throws on mismatched arrays', (t) => {
  const relays = [createMockRelayWithPolicy('relay1', ['Exit'])];
  t.throws(() => pickRelayWeighted(relays, [1, 2]), {
    message: /same length/,
  });
});

test('getBandwidthWeightMultiplier: uses default for missing weights', (t) => {
  const relay = createMockRelayWithPolicy('relay1', ['Guard'], undefined, 1000);

  // Empty bandwidth weights - should use defaults
  const multiplier = getBandwidthWeightMultiplier(relay, 'guard', {});
  t.is(multiplier, 1); // Default weight / default scale = 10000/10000 = 1
});
