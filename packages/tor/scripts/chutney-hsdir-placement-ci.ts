/** Cross-check tor-ts's HSDir ring against descriptors actually published by C Tor. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { makeChutneyTorClient } from '../src/build-circuit/chutney.ts';
import { DirectoryClient } from '../src/directory-client.ts';
import {
  computeTimePeriodInfo,
  deriveBlindedPublicKey,
  fetchHsdirCandidates,
  getFetchSrv,
  parseOnionV3Address,
  selectHsdirsForFetch,
  supportsProtocolVersion,
  toBase64NoPad,
} from '../src/hidden-service.ts';

async function main(): Promise<void> {
  const hostnamePath = process.env.TOR_TS_HS_HOSTNAME_PATH;
  assert(hostnamePath, 'TOR_TS_HS_HOSTNAME_PATH is required');
  const onion = (await readFile(hostnamePath, 'utf8')).trim();
  const { publicIdentityKey } = parseOnionV3Address(onion);
  const client = await makeChutneyTorClient();
  const deadline = Date.now() + 120_000;
  try {
    while (Date.now() < deadline) {
      const consensus = await client.refreshConsensus();
      const { periodLengthMinutes, periodCandidates, nReplicas } = computeTimePeriodInfo(consensus);
      const periodNum = periodCandidates[0]!;
      const srv = getFetchSrv(consensus, periodLengthMinutes, periodNum);
      const nodes = consensus.relays.filter(
        (r) =>
          (r.flags ?? []).includes('HSDir') && supportsProtocolVersion(r.protocols?.HSDir ?? '', 2)
      );
      const candidates = await fetchHsdirCandidates(client.microdescManager, nodes);
      const spreadStore = consensus.params['hsdir_spread_store'] ?? 4;
      const expectedCount = nReplicas * spreadStore;
      assert(
        candidates.length > expectedCount,
        `Need more than ${expectedCount} HSDirs to test non-responsible directories; got ${candidates.length}`
      );
      const blindedKey = deriveBlindedPublicKey({
        publicIdentityKey,
        periodNum,
        periodLengthMinutes,
      });
      const expected = new Set(
        selectHsdirsForFetch({
          hsdirs: candidates,
          sharedRandomValue: srv,
          blindedPublicKey: blindedKey,
          periodLengthMinutes,
          periodNum,
          nReplicas,
          spreadFetch: spreadStore,
        }).map((peer) => peer.rsaIdDigest.toString('hex'))
      );
      assert.equal(expected.size, expectedCount);

      const actual = new Set<string>();
      for (const { peerInfo } of candidates) {
        const circuit = await client.buildCircuitToTarget(peerInfo);
        try {
          // null means an actual HTTP 404. Transport errors and all other status
          // codes throw; they must never count as the negative control passing.
          const descriptor = await new DirectoryClient(circuit, {
            timeoutMs: 10_000,
            maxRetries: 1,
          }).downloadHsDescriptor(toBase64NoPad(blindedKey));
          if (descriptor !== null) actual.add(peerInfo.rsaIdDigest.toString('hex'));
        } finally {
          circuit.destroy({ preserveChannel: true });
        }
      }

      // Chutney rotates quickly. Discard the entire observation if the time
      // period, SRV, or HSDir membership changed during these requests.
      const after = await client.refreshConsensus();
      const afterPeriod = computeTimePeriodInfo(after);
      const afterNodes = after.relays
        .filter(
          (r) =>
            (r.flags ?? []).includes('HSDir') &&
            supportsProtocolVersion(r.protocols?.HSDir ?? '', 2)
        )
        .map((r) => r.rsaIdDigest.toString('hex'))
        .sort();
      if (
        afterPeriod.periodCandidates[0] !== periodNum ||
        afterPeriod.periodLengthMinutes !== periodLengthMinutes ||
        !getFetchSrv(after, periodLengthMinutes, periodNum).equals(srv) ||
        JSON.stringify(afterNodes) !==
          JSON.stringify(nodes.map((r) => r.rsaIdDigest.toString('hex')).sort())
      ) {
        console.log('HSDir snapshot changed during observation; retrying the whole snapshot');
        continue;
      }

      const unexpected = [...actual].filter((id) => !expected.has(id));
      assert.deepEqual(unexpected, [], 'C Tor published to HSDirs outside the calculated ring');
      if (actual.size === expected.size) {
        console.log(
          `HSDir placement passed: ${actual.size} responsible dirs returned 200; ` +
            `${candidates.length - actual.size} non-responsible dirs returned 404`
        );
        return;
      }
      // C Tor may still be finishing its uploads. Retry a complete observation,
      // preserving the requirement that every expected directory eventually has it.
      console.log(
        `Waiting for descriptor publication: ${actual.size}/${expected.size} directories`
      );
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    throw new Error('HSDir placement did not match C Tor publication within 120 seconds');
  } finally {
    client.destroy();
  }
}

main().then(
  () => process.exit(0),
  (error) => {
    console.error(error);
    process.exit(1);
  }
);
