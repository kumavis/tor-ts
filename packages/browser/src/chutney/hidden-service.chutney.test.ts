import { expect, inject, test } from 'vitest';
import { InMemoryMicrodescStorage } from 'tor';
import { makeBrowserTorClient } from '../client.ts';
import './fixture.ts';

test('browser fetches a C Tor onion twice over one Snowflake channel', async () => {
  const fixture = inject('chutney');
  const { client, entryPeerInfo } = await makeBrowserTorClient({
    relayUrl: fixture.relayUrl,
    trustedAuthorities: fixture.trustedAuthorities,
    skipConsensusCache: true,
    microdescStorage: new InMemoryMicrodescStorage(),
    onConsensusUpdate: () => {},
    onStatus: (status) => console.log(`[chutney-browser] ${status}`),
  });
  try {
    // Mainnet Snowflake bridges are not candidates for the HSDir/introduction/
    // rendezvous roles. Require the fixture to model that same topology.
    expect(
      client.consensus.relays.some((r) => r.rsaIdDigest.equals(entryPeerInfo.rsaIdDigest))
    ).toBe(false);
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await client.fetch(fixture.onionUrl, { timeout: 120_000 });
      expect(response.status).toBe(200);
      expect(new TextDecoder().decode(response.body)).toBe(fixture.expectedBody);
      console.log(
        `[chutney-browser] fetch ${attempt + 1}/2: HTTP ${response.status}, ${response.body.length} bytes verified`
      );
      // Exercise the still-live bootstrap circuit after per-fetch cleanup.
      const consensus = await client.refreshConsensus();
      expect(consensus.relays.length).toBeGreaterThan(0);
    }
  } finally {
    client.destroy();
  }
}, 300_000);
