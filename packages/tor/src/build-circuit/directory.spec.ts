/**
 * Tests for directory parsing functions.
 */

import test from 'ava';
import {
  parseRelaysFromMicroDesc,
  parseMicroDescConsensus,
  microDescNodeInfoToPeerInfo,
} from './directory.ts';
import { LinkSpecifierTypes } from '../messaging.ts';

const sampleMicroDesc = `network-status-version 3 microdesc
vote-status consensus
consensus-method 30
valid-after 2024-01-01 00:00:00
fresh-until 2024-01-01 01:00:00
valid-until 2024-01-01 03:00:00
voting-delay 300 300
params bwweightscale=10000 hsdir-interval=1440
shared-rand-previous-value 3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
shared-rand-current-value 3 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
r TestRelay1 AB+0S6hvSEnm7ifzqh3QaYOxsm0 2024-01-01 00:00:00 192.168.1.1 9001 9030
m BY6mSHVSthDKuKGu8aiGKhuGkwZqJqDLs9RxY99gKYs
s Authority Exit Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.4.8.1-alpha-dev
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=158 Unmeasured=1
r TestRelay2 CD+1T7iwTFnm8jgzrh4RbZQysn1 2024-01-01 00:00:00 10.0.0.1 9002 9031
m CZ7nTIWTuhELvMHv9bjHLivHlxZrKrEMs+SyZ+agLZt
s Fast Guard Running Stable Valid
v Tor 0.4.8.0
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=82000
directory-footer
`;

test('parseRelaysFromMicroDesc: parses relay entries', async (t) => {
  const relays = await parseRelaysFromMicroDesc(sampleMicroDesc);

  t.is(relays.length, 2);

  const relay1 = relays[0]!;
  t.is(relay1.nickname, 'TestRelay1');
  t.is(relay1.ip_address, '192.168.1.1');
  t.is(relay1.onion_router_port, 9001);
  t.is(relay1.directory_server_port, 9030);
  t.deepEqual(relay1.flags, [
    'Authority',
    'Exit',
    'Fast',
    'Guard',
    'HSDir',
    'Running',
    'Stable',
    'V2Dir',
    'Valid',
  ]);
  t.is(relay1.version, 'Tor');
  t.truthy(relay1.protocols['Conflux']);
  t.is(relay1.protocols['Conflux'], '1');
  t.truthy(relay1.bandwidthStats);
  t.is(relay1.bandwidthStats!['Bandwidth'], 158);
  t.is(relay1.bandwidthStats!['Unmeasured'], 1);

  const relay2 = relays[1]!;
  t.is(relay2.nickname, 'TestRelay2');
  t.is(relay2.ip_address, '10.0.0.1');
  t.is(relay2.onion_router_port, 9002);
  t.is(relay2.directory_server_port, 9031);
  t.deepEqual(relay2.flags, ['Fast', 'Guard', 'Running', 'Stable', 'Valid']);
});

test('parseMicroDescConsensus: parses consensus metadata', async (t) => {
  // Disable signature verification for unit tests with synthetic data
  const consensus = await parseMicroDescConsensus(sampleMicroDesc, { verifySignatures: false });

  t.truthy(consensus.validAfter);
  t.truthy(consensus.freshUntil);
  t.truthy(consensus.validUntil);

  t.is(consensus.params['bwweightscale'], 10000);
  t.is(consensus.params['hsdir-interval'], 1440);

  t.truthy(consensus.sharedRandPreviousValue);
  t.truthy(consensus.sharedRandCurrentValue);

  t.is(consensus.relays.length, 2);
});

test('parseMicroDescConsensus: handles missing optional fields', async (t) => {
  const minimalDesc = `r MinimalRelay EF+2U8jxUGom9khzsh5ScaRzto2 2024-01-01 00:00:00 1.2.3.4 9001 0
`;

  // Disable signature verification for unit tests with synthetic data
  const consensus = await parseMicroDescConsensus(minimalDesc, { verifySignatures: false });
  t.is(consensus.relays.length, 1);

  const relay = consensus.relays[0]!;
  t.is(relay.nickname, 'MinimalRelay');
  t.is(relay.ip_address, '1.2.3.4');
  t.is(relay.onion_router_port, 9001);
  t.is(relay.directory_server_port, 0);
  t.is(relay.flags, undefined);
  t.is(relay.mKey, undefined);
});

test('parseRelaysFromMicroDesc: parses rsaIdDigest from base64', async (t) => {
  const relays = await parseRelaysFromMicroDesc(sampleMicroDesc);
  const relay = relays[0]!;

  // rsaIdDigest should be a 20-byte buffer decoded from base64
  t.true(Buffer.isBuffer(relay.rsaIdDigest));
  t.is(relay.rsaIdDigest.length, 20);
});

test('parseRelaysFromMicroDesc: parses mKey from base64', async (t) => {
  const relays = await parseRelaysFromMicroDesc(sampleMicroDesc);
  const relay = relays[0]!;

  t.truthy(relay.mKey);
  t.true(Buffer.isBuffer(relay.mKey));
});

test('parseRelaysFromMicroDesc: parses protocols', async (t) => {
  const relays = await parseRelaysFromMicroDesc(sampleMicroDesc);
  const relay = relays[0]!;

  t.is(relay.protocols['Conflux'], '1');
  t.is(relay.protocols['Cons'], '1-2');
  t.is(relay.protocols['Link'], '1-5');
  t.is(relay.protocols['LinkAuth'], '1,3');
});

test('microDescNodeInfoToPeerInfo: creates PeerInfo with correct link specifiers', async (t) => {
  const relays = await parseRelaysFromMicroDesc(sampleMicroDesc);
  const nodeInfo = relays[0]!;
  const onionKey = Buffer.alloc(32).fill(0x42);

  const peerInfo = microDescNodeInfoToPeerInfo(nodeInfo, onionKey);

  t.deepEqual(peerInfo.onionKey, onionKey);
  t.deepEqual(peerInfo.rsaIdDigest, nodeInfo.rsaIdDigest);

  // Should have at least 2 link specifiers: IPv4 address and legacy ID
  t.true(peerInfo.linkSpecifiers.length >= 2);

  // First should be TlsOverTcpIPv4
  const ipv4Spec = peerInfo.linkSpecifiers.find(
    (ls) => ls.type === LinkSpecifierTypes.TlsOverTcpIPv4
  );
  t.truthy(ipv4Spec);
  t.is(ipv4Spec!.data.length, 6); // 4 bytes IP + 2 bytes port

  // Should have legacy ID
  const legacyIdSpec = peerInfo.linkSpecifiers.find(
    (ls) => ls.type === LinkSpecifierTypes.LegacyId
  );
  t.truthy(legacyIdSpec);
  t.is(legacyIdSpec!.data.length, 20); // SHA1 fingerprint
});

test('parseRelaysFromMicroDesc: handles empty input', async (t) => {
  const relays = await parseRelaysFromMicroDesc('');
  t.is(relays.length, 0);
});

test('parseRelaysFromMicroDesc: handles input with no relay entries', async (t) => {
  const headerOnly = `network-status-version 3 microdesc
vote-status consensus
valid-after 2024-01-01 00:00:00
directory-footer
`;

  const relays = await parseRelaysFromMicroDesc(headerOnly);
  t.is(relays.length, 0);
});
