/**
 * Tests for circuit operations.
 */

import test from 'ava';
import { circuitIdLengthForProtocolVersion } from './circuit.ts';

test('circuitIdLengthForProtocolVersion: returns 2 for version undefined', (t) => {
  const length = circuitIdLengthForProtocolVersion(undefined);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 1', (t) => {
  const length = circuitIdLengthForProtocolVersion(1);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 2', (t) => {
  const length = circuitIdLengthForProtocolVersion(2);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 3', (t) => {
  const length = circuitIdLengthForProtocolVersion(3);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 4 for version 4', (t) => {
  const length = circuitIdLengthForProtocolVersion(4);
  t.is(length, 4);
});

test('circuitIdLengthForProtocolVersion: returns 4 for version 5', (t) => {
  const length = circuitIdLengthForProtocolVersion(5);
  t.is(length, 4);
});
