/**
 * Test script to fetch microdescriptors from the real Tor network
 * and verify hash matching.
 *
 * Run: npx tsx scripts/test-microdesc-fetch.ts
 */

import { makeNodejsTorClient } from '../src/build-circuit/node-client.ts';
import { parseMicrodescriptorBatch } from '../src/directory-client.ts';
import { sha256 } from 'tor-crypto';

async function main() {
  console.log('Creating Tor client...');
  const client = await makeNodejsTorClient({
    onStatus: (msg) => console.log(`[status] ${msg}`),
  });

  console.log('\nConnected to Tor network!');

  // Get the consensus and find some HSDir nodes
  const consensus = client.consensus;
  const relays = consensus.relays;

  // Find nodes with mKey (microdescriptor digest)
  const nodesWithMKey = relays.filter((r) => r.mKey);
  console.log(`\nFound ${nodesWithMKey.length} nodes with microdescriptor digests`);

  // Take a larger sample for testing (one full batch)
  const sampleSize = 92;
  const sampleNodes = nodesWithMKey.slice(0, sampleSize);

  // Convert mKey buffers to base64
  const digestsBase64 = sampleNodes.map((n) => n.mKey!.toString('base64').replace(/=+$/, ''));

  console.log(`\nRequesting ${sampleSize} microdescriptors:`);
  for (const d of digestsBase64) {
    console.log(`  ${d}`);
  }

  // Fetch microdescriptors
  const dirClient = client.dirClient;
  console.log('\nFetching from directory...');

  const content = await dirClient.downloadMicrodescriptors(digestsBase64);

  console.log(`\nReceived ${content.length} bytes`);
  console.log(`Starts with: ${JSON.stringify(content.slice(0, 100))}`);
  console.log(`Ends with: ${JSON.stringify(content.slice(-100))}`);

  // Find microdescriptor boundaries
  const boundaries: number[] = [];
  const startPattern = /(?:^|\n)(onion-key\r?\n)/g;
  let match;
  while ((match = startPattern.exec(content)) !== null) {
    boundaries.push(match.index === 0 ? 0 : match.index + 1);
  }
  boundaries.sort((a, b) => a - b);

  console.log(`\nFound ${boundaries.length} microdescriptor boundaries`);

  // Compute hashes and check matches
  console.log('\nHash matching analysis:');
  const expectedDigests = new Set(digestsBase64);
  let matchCount = 0;
  let unmatchedCount = 0;

  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i]!;
    const end = i + 1 < boundaries.length ? boundaries[i + 1]! : content.length;
    const text = content.slice(start, end);

    const hash = sha256(Buffer.from(text));
    const hashB64 = hash.toString('base64').replace(/=+$/, '');

    if (expectedDigests.has(hashB64)) {
      matchCount++;
    } else {
      unmatchedCount++;
      if (unmatchedCount <= 3) {
        console.log(`\n  Unmatched microdesc ${i + 1}:`);
        console.log(`    Computed hash: ${hashB64}`);
        console.log(`    First 100 chars: ${JSON.stringify(text.slice(0, 100))}`);
      }
    }
  }

  console.log(
    `\n\nSUMMARY: ${matchCount}/${boundaries.length} hashes match (${Math.round((matchCount / boundaries.length) * 100)}%)`
  );

  // Try using parseMicrodescriptorBatch
  console.log('\nTrying parseMicrodescriptorBatch:');
  const parsed = parseMicrodescriptorBatch(content, digestsBase64);
  console.log(`  Parsed ${parsed.size} microdescriptors`);

  for (const [digest, md] of parsed) {
    console.log(
      `  ${digest}: ntor=${md.ntorOnionKey?.length ?? 'none'}, ed25519=${md.ed25519Identity?.length ?? 'none'}`
    );
  }

  // Clean up
  client.destroy();
  console.log('\nDone!');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
