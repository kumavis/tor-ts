import test from 'ava';
import { x25519 } from 'tor-crypto';
import { Circuit, type PeerInfo } from './circuit.ts';
import type { ChannelConnection } from './channel.ts';
import { RelayCell } from './relay-cell.ts';
import {
  buildIntroduce1Payload,
  connectToHiddenServiceCore,
  HsDescriptorCache,
  parseOnionV3Address,
  type HsConnectionContext,
} from './hidden-service.ts';
import {
  completeHsNtorServer,
  decryptIntroduce2,
  generateIntroPointKeys,
  parseIntroduce2,
} from './hidden-service-host.ts';

const ONION = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion';

function makeHarness(
  options: {
    statuses?: number[];
    rendezvous?: 'success' | 'missing' | 'invalid';
    failEstablish?: boolean;
  } = {}
) {
  const onionKey = Buffer.from(x25519.getPublicKey(Buffer.alloc(32, 7)));
  const peer: PeerInfo = {
    onionKey,
    rsaIdDigest: Buffer.alloc(20, 3),
    linkSpecifiers: [
      { type: 0, data: Buffer.from([127, 0, 0, 1, 0x23, 0x29]) },
      { type: 2, data: Buffer.alloc(20, 3) },
      { type: 3, data: Buffer.alloc(32, 4) },
    ],
  };
  const intro = generateIntroPointKeys(peer, Buffer.alloc(32, 4));
  const subcredential = Buffer.alloc(32, 6);
  const cache = new HsDescriptorCache();
  cache.set(
    parseOnionV3Address(ONION).publicIdentityKey,
    {
      introPoints: [
        {
          linkSpecifiers: peer.linkSpecifiers,
          introPointOnionKey: onionKey,
          authKeyEd25519: intro.authKeyPublic,
          serviceEncKey: intro.encKeyPublic,
        },
      ],
    },
    Buffer.alloc(32, 5),
    subcredential
  );
  const relay = {
    nickname: 'mock',
    rsaIdDigest: Buffer.alloc(20, 1),
    publication_date: new Date(),
    ip_address: '127.0.0.1',
    onion_router_port: 9001,
    directory_server_port: 0,
    mKey: Buffer.alloc(32, 2),
    flags: ['HSDir'],
    protocols: { HSDir: '2', HSRend: '2' },
  };
  const channel = {
    destroyed: false,
    getProtocolVersion: () => 4,
    subscribeCircuit: () => () => {},
    destroy() {
      this.destroyed = true;
    },
  };
  const circuits: Circuit[] = [];
  let introductions = 0;
  const ctx = {
    consensus: { validAfter: new Date(), relays: [relay], params: {} },
    dirClient: {
      downloadRelayServerDescriptor: async () =>
        `ntor-onion-key ${onionKey.toString('base64')}\nmaster-key-ed25519 ${Buffer.alloc(32, 8).toString('base64')}\n`,
    },
    microdescManager: {
      get: async () =>
        new Map([
          [
            relay.mKey.toString('base64').replace(/=+$/, ''),
            { ntorOnionKey: onionKey, ed25519Identity: Buffer.alloc(32, 8) },
          ],
        ]),
    },
    buildCircuit: async () => {
      if (channel.destroyed) throw new Error('shared channel closed');
      const circuit = new Circuit({ path: [], channel: channel as unknown as ChannelConnection });
      circuits.push(circuit);
      circuit.sendRelayMessage = async ({ relayCommand, data }) => {
        if (relayCommand === RelayCell.ESTABLISH_RENDEZVOUS) {
          if (options.failEstablish) throw new Error('establish failed');
          setImmediate(() =>
            circuit.emit('relay', {
              streamId: 0,
              relayCommand: RelayCell.RENDEZVOUS_ESTABLISHED,
              data: Buffer.alloc(0),
            })
          );
        }
        if (relayCommand === RelayCell.INTRODUCE1) {
          const status = options.statuses?.[introductions++] ?? 0;
          const parsed = parseIntroduce2(data);
          const response = completeHsNtorServer({
            clientPk: parsed.clientPk,
            introPoint: intro,
            subcredential,
          });
          setImmediate(() => {
            circuit.emit('relay', {
              streamId: 0,
              relayCommand: RelayCell.INTRODUCE_ACK,
              data: Buffer.from([0, status]),
            });
            if (status === 0 && options.rendezvous !== 'missing') {
              circuits[0]!.emit('relay', {
                streamId: 0,
                relayCommand: RelayCell.RENDEZVOUS2,
                data:
                  options.rendezvous === 'invalid'
                    ? Buffer.concat([response.rendezvous1Data.subarray(0, 32), Buffer.alloc(32)])
                    : response.rendezvous1Data,
              });
            }
          });
        }
      };
      return circuit;
    },
  } as unknown as HsConnectionContext;
  const connect = () =>
    connectToHiddenServiceCore(ctx, ONION, {
      descriptorCache: cache,
      maxIntroAttempts: 2,
      overallTimeoutMs: 2000,
      perHandshakeTimeoutMs: 200,
      rendezvousTimeoutMs: 20,
    });
  return {
    connect,
    channel,
    circuits,
    ctx,
    peer,
    intro,
    subcredential,
    get introductions() {
      return introductions;
    },
  };
}

test('HS retries an intro NACK on the same channel and completes rendezvous', async (t) => {
  const h = makeHarness({ statuses: [2, 0] });
  const result = await h.connect();
  t.is(h.introductions, 2);
  t.false(h.channel.destroyed);
  t.true(h.circuits[1]!.isDestroyed);
  t.true(h.circuits[2]!.isDestroyed);
  t.false(result.circuit.isDestroyed);
  t.is(result.circuit.hops.length, 1, 'completed the service virtual hop');
  result.circuit.destroy({ preserveChannel: true });
});

for (const scenario of [
  { name: 'all introductions fail', options: { statuses: [2, 2] }, error: /All 2 introduction/ },
  { name: 'establish fails', options: { failEstablish: true }, error: /establish failed/ },
  {
    name: 'rendezvous times out',
    options: { rendezvous: 'missing' as const },
    error: /Rendezvous failed/,
  },
  {
    name: 'rendezvous response is invalid',
    options: { rendezvous: 'invalid' as const },
    error: /AUTH_INPUT_MAC/,
  },
]) {
  test(`HS releases owned circuits and preserves shared channel when ${scenario.name}`, async (t) => {
    const h = makeHarness(scenario.options);
    await t.throwsAsync(h.connect, { message: scenario.error });
    t.false(h.channel.destroyed);
    t.true(h.circuits.every((circuit) => circuit.isDestroyed));
    const next = await h.ctx.buildCircuit(h.peer);
    t.false(next.isDestroyed, 'another operation can use the shared channel');
    next.destroy({ preserveChannel: true });
  });
}

for (const withExtensions of [false, true]) {
  test(`INTRODUCE1 full payload fits 490 bytes ${withExtensions ? 'with PoW and CC extensions' : 'without extensions'}`, async (t) => {
    const h = makeHarness();
    const cookie = Buffer.alloc(20, 9);
    const { payload } = await buildIntroduce1Payload({
      introAuthKeyEd25519: h.intro.authKeyPublic,
      serviceEncKey: h.intro.encKeyPublic,
      N_hs_subcred: h.subcredential,
      rendezvousCookie: cookie,
      rendezvousPoint: h.peer,
      ...(withExtensions
        ? {
            requestCongestionControl: true,
            proofOfWork: {
              scheme: 1,
              nonce: Buffer.alloc(16, 1),
              effort: 1,
              seed: Buffer.alloc(4, 2),
              solution: Buffer.alloc(16, 3),
            },
          }
        : {}),
    });
    t.is(payload.length, 490, 'the limit includes the unencrypted header');
    const decrypted = await decryptIntroduce2({
      parsed: parseIntroduce2(payload),
      introPoint: h.intro,
      subcredential: h.subcredential,
    });
    t.deepEqual(decrypted.rendezvousCookie, cookie, 'padding preserves the forwarded payload');
  });
}
