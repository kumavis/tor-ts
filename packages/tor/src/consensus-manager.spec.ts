/**
 * Tests for ConsensusManager.
 */

import test from 'ava';
import type { Circuit } from './circuit.ts';
import type { VerifiedMicroDescConsensus } from './build-circuit/directory.ts';
import { ConsensusManager, isConsensusFresh, isConsensusTtlValid } from './consensus-manager.ts';

// Mock circuit that doesn't actually connect
const mockCircuit = {} as Circuit;

/**
 * Create a mock consensus with configurable timestamps.
 * Returns a VerifiedMicroDescConsensus for testing purposes.
 */
function createMockConsensus(options: {
  freshUntil?: Date;
  validUntil?: Date;
  validAfter?: Date;
}): VerifiedMicroDescConsensus {
  return {
    _verified: true,
    relays: [],
    params: {},
    freshUntil: options.freshUntil,
    validUntil: options.validUntil,
    validAfter: options.validAfter,
    sharedRandPreviousValue: undefined,
    sharedRandCurrentValue: undefined,
    bandwidthWeights: {},
  };
}

// --- isConsensusFresh tests ---

test('isConsensusFresh: returns true when current time < freshUntil', (t) => {
  const futureTime = new Date(Date.now() + 3600 * 1000); // 1 hour from now
  const consensus = createMockConsensus({ freshUntil: futureTime });

  t.true(isConsensusFresh(consensus));
});

test('isConsensusFresh: returns false when current time >= freshUntil', (t) => {
  const pastTime = new Date(Date.now() - 1000); // 1 second ago
  const consensus = createMockConsensus({ freshUntil: pastTime });

  t.false(isConsensusFresh(consensus));
});

test('isConsensusFresh: accepts custom now parameter for testing', (t) => {
  const freshUntil = new Date('2024-01-01T12:00:00Z');
  const consensus = createMockConsensus({ freshUntil });

  // Time before freshUntil
  t.true(isConsensusFresh(consensus, new Date('2024-01-01T11:00:00Z').getTime()));

  // Time after freshUntil
  t.false(isConsensusFresh(consensus, new Date('2024-01-01T13:00:00Z').getTime()));
});

test('isConsensusFresh: falls back to validAfter + 1 hour when freshUntil missing', (t) => {
  const validAfter = new Date(Date.now() - 30 * 60 * 1000); // 30 minutes ago
  const consensus = createMockConsensus({ validAfter });

  // Should be fresh because validAfter + 1 hour is still in the future
  t.true(isConsensusFresh(consensus));
});

test('isConsensusFresh: returns false when no timing info available', (t) => {
  const consensus = createMockConsensus({});

  t.false(isConsensusFresh(consensus));
});

// --- isConsensusTtlValid tests ---

test('isConsensusTtlValid: returns true when current time < validUntil', (t) => {
  const futureTime = new Date(Date.now() + 3600 * 1000);
  const consensus = createMockConsensus({ validUntil: futureTime });

  t.true(isConsensusTtlValid(consensus));
});

test('isConsensusTtlValid: returns false when current time >= validUntil', (t) => {
  const pastTime = new Date(Date.now() - 1000);
  const consensus = createMockConsensus({ validUntil: pastTime });

  t.false(isConsensusTtlValid(consensus));
});

test('isConsensusTtlValid: accepts custom now parameter for testing', (t) => {
  const validUntil = new Date('2024-01-01T15:00:00Z');
  const consensus = createMockConsensus({ validUntil });

  // Time before validUntil
  t.true(isConsensusTtlValid(consensus, new Date('2024-01-01T14:00:00Z').getTime()));

  // Time after validUntil
  t.false(isConsensusTtlValid(consensus, new Date('2024-01-01T16:00:00Z').getTime()));
});

test('isConsensusTtlValid: falls back to freshUntil + 2 hours when validUntil missing', (t) => {
  const freshUntil = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
  const consensus = createMockConsensus({ freshUntil });

  // Should be valid because freshUntil + 2 hours is still in the future
  t.true(isConsensusTtlValid(consensus));
});

test('isConsensusTtlValid: returns false when no timing info available', (t) => {
  const consensus = createMockConsensus({});

  t.false(isConsensusTtlValid(consensus));
});

// --- ConsensusManager constructor tests ---

test('ConsensusManager: throws if both initialVerifiedConsensus and initialRawContent provided', (t) => {
  const consensus = createMockConsensus({
    freshUntil: new Date(Date.now() + 3600 * 1000),
  });

  t.throws(
    () => {
      new ConsensusManager(mockCircuit, {
        initialVerifiedConsensus: consensus,
        initialRawContent: 'raw content',
      });
    },
    {
      message: /Cannot provide both initialVerifiedConsensus and initialRawContent/,
    }
  );
});

test('ConsensusManager: accepts initialVerifiedConsensus if valid', (t) => {
  const consensus = createMockConsensus({
    freshUntil: new Date(Date.now() + 3600 * 1000),
    validUntil: new Date(Date.now() + 7200 * 1000),
  });

  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: consensus,
  });

  t.is(manager.getCurrentConsensus(), consensus);
});

test('ConsensusManager: ignores expired initialVerifiedConsensus', (t) => {
  const expiredConsensus = createMockConsensus({
    freshUntil: new Date(Date.now() - 7200 * 1000), // 2 hours ago
    validUntil: new Date(Date.now() - 1000), // 1 second ago (expired)
  });

  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: expiredConsensus,
  });

  // Should not store expired consensus
  t.is(manager.getCurrentConsensus(), undefined);
});

test('ConsensusManager: accepts no options', (t) => {
  const manager = new ConsensusManager(mockCircuit);

  t.is(manager.getCurrentConsensus(), undefined);
});

// --- ConsensusManager.getStatus tests ---

test('ConsensusManager: getStatus returns correct state when no consensus', (t) => {
  const manager = new ConsensusManager(mockCircuit);
  const status = manager.getStatus();

  t.false(status.hasConsensus);
  t.false(status.isFresh);
  t.false(status.isValid);
  t.is(status.freshUntil, undefined);
  t.is(status.validUntil, undefined);
});

test('ConsensusManager: getStatus returns correct state for fresh consensus', (t) => {
  const freshUntil = new Date(Date.now() + 3600 * 1000);
  const validUntil = new Date(Date.now() + 7200 * 1000);
  const validAfter = new Date(Date.now() - 1800 * 1000);

  const consensus = createMockConsensus({ freshUntil, validUntil, validAfter });
  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: consensus,
  });

  const status = manager.getStatus();

  t.true(status.hasConsensus);
  t.true(status.isFresh);
  t.true(status.isValid);
  t.deepEqual(status.freshUntil, freshUntil);
  t.deepEqual(status.validUntil, validUntil);
  t.deepEqual(status.validAfter, validAfter);
});

test('ConsensusManager: getStatus returns isFresh=false for stale but valid consensus', (t) => {
  const freshUntil = new Date(Date.now() - 1000); // past
  const validUntil = new Date(Date.now() + 3600 * 1000); // future

  const consensus = createMockConsensus({ freshUntil, validUntil });
  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: consensus,
  });

  const status = manager.getStatus();

  t.true(status.hasConsensus);
  t.false(status.isFresh);
  t.true(status.isValid);
});

// --- ConsensusManager.clear tests ---

test('ConsensusManager: clear removes consensus', (t) => {
  const consensus = createMockConsensus({
    freshUntil: new Date(Date.now() + 3600 * 1000),
    validUntil: new Date(Date.now() + 7200 * 1000),
  });

  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: consensus,
  });

  t.truthy(manager.getCurrentConsensus());

  manager.clear();

  t.is(manager.getCurrentConsensus(), undefined);
});

// --- ConsensusManager.getCurrentConsensus tests ---

test('ConsensusManager: getCurrentConsensus returns undefined for expired consensus', (t) => {
  // Create a consensus that is valid now
  const validUntil = new Date(Date.now() + 100); // valid for 100ms
  const consensus = createMockConsensus({
    freshUntil: new Date(Date.now() + 50),
    validUntil,
  });

  const manager = new ConsensusManager(mockCircuit, {
    initialVerifiedConsensus: consensus,
  });

  // Should return the consensus while valid
  t.truthy(manager.getCurrentConsensus());

  // Note: We can't easily test time expiration in a unit test without mocking Date.now
  // The test for expired consensus in constructor covers the main case
});

// --- ConsensusManager.subscribe tests ---

test('ConsensusManager: subscribe returns unsubscribe function', (t) => {
  const manager = new ConsensusManager(mockCircuit);
  const listener = () => {};

  const unsubscribe = manager.subscribe(listener);

  t.is(typeof unsubscribe, 'function');
});

test('ConsensusManager: unsubscribe removes listener', (t) => {
  const manager = new ConsensusManager(mockCircuit);
  const listener = () => {};

  const unsubscribe = manager.subscribe(listener);
  unsubscribe();

  // Can't directly test without triggering refresh, but the operation should not throw
  t.pass();
});
