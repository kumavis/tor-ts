import test from 'ava';
import {
  parsePortList,
  parseExitPolicySummary,
  policyAllowsPort,
  policyAllowsAllPorts,
  policyAllowsAnyPort,
  policyRejectsAll,
  DEFAULT_TARGET_PORTS,
} from './exit-policy.ts';

// parsePortList tests
test('parsePortList: single port', (t) => {
  const result = parsePortList('80');
  t.deepEqual(result, [{ start: 80, end: 80 }]);
});

test('parsePortList: multiple ports', (t) => {
  const result = parsePortList('80,443,8080');
  t.deepEqual(result, [
    { start: 80, end: 80 },
    { start: 443, end: 443 },
    { start: 8080, end: 8080 },
  ]);
});

test('parsePortList: port range', (t) => {
  const result = parsePortList('8000-9000');
  t.deepEqual(result, [{ start: 8000, end: 9000 }]);
});

test('parsePortList: mixed ports and ranges', (t) => {
  const result = parsePortList('80,443,8000-9000');
  t.deepEqual(result, [
    { start: 80, end: 80 },
    { start: 443, end: 443 },
    { start: 8000, end: 9000 },
  ]);
});

test('parsePortList: full range', (t) => {
  const result = parsePortList('1-65535');
  t.deepEqual(result, [{ start: 1, end: 65535 }]);
});

test('parsePortList: empty string', (t) => {
  const result = parsePortList('');
  t.deepEqual(result, []);
});

test('parsePortList: handles whitespace', (t) => {
  const result = parsePortList(' 80 , 443 ');
  t.deepEqual(result, [
    { start: 80, end: 80 },
    { start: 443, end: 443 },
  ]);
});

// parseExitPolicySummary tests
test('parseExitPolicySummary: accept with p prefix', (t) => {
  const result = parseExitPolicySummary('p accept 80,443');
  t.deepEqual(result, {
    type: 'accept',
    ports: [
      { start: 80, end: 80 },
      { start: 443, end: 443 },
    ],
  });
});

test('parseExitPolicySummary: reject with p prefix', (t) => {
  const result = parseExitPolicySummary('p reject 25,119,135-139,445');
  t.deepEqual(result, {
    type: 'reject',
    ports: [
      { start: 25, end: 25 },
      { start: 119, end: 119 },
      { start: 135, end: 139 },
      { start: 445, end: 445 },
    ],
  });
});

test('parseExitPolicySummary: accept without p prefix', (t) => {
  const result = parseExitPolicySummary('accept 80,443');
  t.deepEqual(result, {
    type: 'accept',
    ports: [
      { start: 80, end: 80 },
      { start: 443, end: 443 },
    ],
  });
});

test('parseExitPolicySummary: reject all', (t) => {
  const result = parseExitPolicySummary('p reject 1-65535');
  t.deepEqual(result, {
    type: 'reject',
    ports: [{ start: 1, end: 65535 }],
  });
});

test('parseExitPolicySummary: accept all', (t) => {
  const result = parseExitPolicySummary('p accept 1-65535');
  t.deepEqual(result, {
    type: 'accept',
    ports: [{ start: 1, end: 65535 }],
  });
});

test('parseExitPolicySummary: invalid returns null', (t) => {
  t.is(parseExitPolicySummary('invalid'), null);
  t.is(parseExitPolicySummary('p invalid 80'), null);
});

// policyAllowsPort tests
test('policyAllowsPort: accept policy allows listed port', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.true(policyAllowsPort(policy, 80));
  t.true(policyAllowsPort(policy, 443));
});

test('policyAllowsPort: accept policy rejects unlisted port', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.false(policyAllowsPort(policy, 22));
  t.false(policyAllowsPort(policy, 8080));
});

test('policyAllowsPort: reject policy allows unlisted port', (t) => {
  const policy = parseExitPolicySummary('p reject 25,445');
  t.true(policyAllowsPort(policy, 80));
  t.true(policyAllowsPort(policy, 443));
});

test('policyAllowsPort: reject policy rejects listed port', (t) => {
  const policy = parseExitPolicySummary('p reject 25,445');
  t.false(policyAllowsPort(policy, 25));
  t.false(policyAllowsPort(policy, 445));
});

test('policyAllowsPort: port in range', (t) => {
  const policy = parseExitPolicySummary('p accept 8000-9000');
  t.true(policyAllowsPort(policy, 8000));
  t.true(policyAllowsPort(policy, 8500));
  t.true(policyAllowsPort(policy, 9000));
  t.false(policyAllowsPort(policy, 7999));
  t.false(policyAllowsPort(policy, 9001));
});

test('policyAllowsPort: null policy returns true (permissive)', (t) => {
  t.true(policyAllowsPort(null, 80));
  t.true(policyAllowsPort(undefined, 443));
});

// policyAllowsAllPorts tests
test('policyAllowsAllPorts: all ports allowed', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443,8080');
  t.true(policyAllowsAllPorts(policy, [80, 443]));
});

test('policyAllowsAllPorts: some ports not allowed', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.false(policyAllowsAllPorts(policy, [80, 22]));
});

test('policyAllowsAllPorts: empty ports array', (t) => {
  const policy = parseExitPolicySummary('p accept 80');
  t.true(policyAllowsAllPorts(policy, []));
});

// policyAllowsAnyPort tests
test('policyAllowsAnyPort: some port allowed', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.true(policyAllowsAnyPort(policy, [22, 80]));
});

test('policyAllowsAnyPort: no ports allowed', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.false(policyAllowsAnyPort(policy, [22, 25]));
});

// policyRejectsAll tests
test('policyRejectsAll: reject 1-65535', (t) => {
  const policy = parseExitPolicySummary('p reject 1-65535');
  t.true(policyRejectsAll(policy));
});

test('policyRejectsAll: accept with no ports', (t) => {
  const policy = { type: 'accept' as const, ports: [] };
  t.true(policyRejectsAll(policy));
});

test('policyRejectsAll: normal accept policy', (t) => {
  const policy = parseExitPolicySummary('p accept 80,443');
  t.false(policyRejectsAll(policy));
});

test('policyRejectsAll: null policy', (t) => {
  t.false(policyRejectsAll(null));
});

// DEFAULT_TARGET_PORTS
test('DEFAULT_TARGET_PORTS includes HTTP and HTTPS', (t) => {
  t.deepEqual(DEFAULT_TARGET_PORTS, [80, 443]);
});
