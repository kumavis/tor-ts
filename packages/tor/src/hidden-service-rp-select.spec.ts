/**
 * Unit tests for hidden-service.ts's rendezvous-point selection filter.
 *
 * The chutney CI log on b94cd07 showed we were picking the Exit relay as RP
 * on a 7-node network, which starved the HS's own circuit-build path and
 * reproduced a silent rendezvous failure. Canonical tor explicitly avoids
 * Authority and Exit flags when picking RP; pickRendezvousPoint() does too.
 */

import test from 'ava';
import { pickRendezvousPoint } from './hidden-service.ts';
import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './build-circuit/directory.ts';

function makeRelay(partial: Partial<MicroDescNodeInfo>): MicroDescNodeInfo {
  return {
    nickname: 'test',
    rsaIdDigest: Buffer.alloc(20, 0),
    publication_date: new Date(),
    ip_address: '127.0.0.1',
    onion_router_port: 9000,
    directory_server_port: 7000,
    protocols: { HSRend: '1-2' },
    ...partial,
  };
}

function makeConsensus(relays: MicroDescNodeInfo[]): VerifiedMicroDescConsensus {
  return {
    relays,
    validAfter: new Date(0),
    freshUntil: new Date(3600000),
    validUntil: new Date(7200000),
    params: {},
    sharedRandCurrentValue: undefined,
    sharedRandPreviousValue: undefined,
    signatures: [],
    validSignatureCount: 0,
    requiredSignatureCount: 0,
    totalKnownAuthorities: 0,
  } as unknown as VerifiedMicroDescConsensus;
}

test('pickRendezvousPoint: excludes Authority and Exit relays', (t) => {
  const relays = [
    makeRelay({ nickname: 'auth0', flags: ['Authority', 'Fast'] }),
    makeRelay({ nickname: 'auth1', flags: ['Authority', 'Fast'] }),
    makeRelay({ nickname: 'exit0', flags: ['Exit', 'Fast'] }),
    makeRelay({ nickname: 'middle0', flags: ['Fast', 'Stable'] }),
    makeRelay({ nickname: 'middle1', flags: ['Fast', 'Stable'] }),
  ];
  const consensus = makeConsensus(relays);

  // Run many selections to smoke out any bias.
  const nicks = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const { node, qualifiedCount } = pickRendezvousPoint(consensus);
    t.is(qualifiedCount, 2, 'only middle0 and middle1 qualify');
    t.false((node.flags ?? []).includes('Authority'), `should skip Authority (${node.nickname})`);
    t.false((node.flags ?? []).includes('Exit'), `should skip Exit (${node.nickname})`);
    nicks.add(node.nickname);
  }
  t.deepEqual([...nicks].sort(), ['middle0', 'middle1']);
});

test('pickRendezvousPoint: rejects relays without HSRend=2', (t) => {
  const relays = [
    makeRelay({ nickname: 'old', flags: ['Fast'], protocols: { HSRend: '1' } }),
    makeRelay({ nickname: 'ok', flags: ['Fast'], protocols: { HSRend: '1-2' } }),
  ];
  const { node, qualifiedCount } = pickRendezvousPoint(makeConsensus(relays));
  t.is(node.nickname, 'ok');
  t.is(qualifiedCount, 1);
});

test('pickRendezvousPoint: relay with no explicit HSRend field is accepted', (t) => {
  const relays = [makeRelay({ nickname: 'implicit', flags: ['Fast'], protocols: {} })];
  const { node, qualifiedCount } = pickRendezvousPoint(makeConsensus(relays));
  t.is(node.nickname, 'implicit');
  t.is(qualifiedCount, 1);
});

test('pickRendezvousPoint: falls back to non-auth if no full match', (t) => {
  // All non-authority relays are Exits — canonical pick would want an
  // Exit-less non-authority but none exists. Helper should still return a
  // non-authority relay rather than refusing, and report qualifiedCount=0.
  const relays = [
    makeRelay({ nickname: 'auth0', flags: ['Authority', 'Fast'] }),
    makeRelay({ nickname: 'exit0', flags: ['Exit', 'Fast'] }),
    makeRelay({ nickname: 'exit1', flags: ['Exit', 'Fast'] }),
  ];
  const { node, qualifiedCount } = pickRendezvousPoint(makeConsensus(relays));
  t.is(qualifiedCount, 0);
  t.false((node.flags ?? []).includes('Authority'));
  t.true((node.flags ?? []).includes('Exit'));
});

test('pickRendezvousPoint: falls back to any relay if only authorities exist', (t) => {
  const relays = [
    makeRelay({ nickname: 'auth0', flags: ['Authority', 'Fast'] }),
    makeRelay({ nickname: 'auth1', flags: ['Authority', 'Fast'] }),
  ];
  const { node, qualifiedCount } = pickRendezvousPoint(makeConsensus(relays));
  t.is(qualifiedCount, 0);
  t.true((node.flags ?? []).includes('Authority'), 'last-resort fallback');
});

test('pickRendezvousPoint: chutney-shaped 7-node network never picks the Exit', (t) => {
  // Mirrors the actual chutney network shape:
  //   4 authorities (which are also relays),
  //   2 non-exit relays,
  //   1 exit relay.
  const relays = [
    makeRelay({ nickname: 'test000a', flags: ['Authority', 'V2Dir', 'Fast'] }),
    makeRelay({ nickname: 'test001a', flags: ['Authority', 'V2Dir', 'Fast'] }),
    makeRelay({ nickname: 'test002a', flags: ['Authority', 'V2Dir', 'Fast'] }),
    makeRelay({ nickname: 'test003a', flags: ['Authority', 'V2Dir', 'Fast'] }),
    makeRelay({ nickname: 'test004m', flags: ['Fast', 'Stable', 'HSDir'] }),
    makeRelay({ nickname: 'test005m', flags: ['Fast', 'Stable', 'HSDir'] }),
    makeRelay({ nickname: 'test006r', flags: ['Exit', 'Fast', 'Stable'] }),
  ];
  const consensus = makeConsensus(relays);
  for (let i = 0; i < 200; i++) {
    const { node } = pickRendezvousPoint(consensus);
    t.false((node.flags ?? []).includes('Exit'));
    t.false((node.flags ?? []).includes('Authority'));
    t.true(['test004m', 'test005m'].includes(node.nickname));
  }
});
