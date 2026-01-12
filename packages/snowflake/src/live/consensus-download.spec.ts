/**
 * Live test for consensus download via Snowflake.
 *
 * This test validates the circuit-level flow control (proposal 289 authenticated SENDME)
 * by downloading the full microdescriptor consensus (~2-3MB) through a 1-hop bootstrap
 * circuit using CREATE_FAST.
 */

import test from 'ava';
import { SnowflakeWsStack } from '../snowflake-ws-stack.ts';
import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { DirectoryClient } from 'tor/directory-client';
import type { DownloadProgress } from 'tor/directory-client';

// Tests circuit-level flow control (proposal 289 authenticated SENDME) by downloading a large file
test('downloads full consensus via circuit SENDME flow control', async (t) => {
  const relayUrl = 'wss://snowflake.torproject.net/';

  console.log('[test] Connecting to Snowflake...');
  const stack = new SnowflakeWsStack({ relayUrl });
  await stack.connect();
  console.log('[test] Snowflake connected');

  console.log('[test] Creating Tor channel...');
  const channel = new SnowflakeTlsChannelConnection(stack);
  await channel.connect();
  console.log('[test] Tor channel connected');

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    t.fail('No peer identity');
    return;
  }

  // Build 1-hop bootstrap circuit using CREATE_FAST
  console.log('[test] Building bootstrap circuit...');
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0), // Empty triggers CREATE_FAST
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();
  console.log('[test] Bootstrap circuit connected');

  // Download consensus with progress tracking
  console.log('[test] Starting consensus download...');
  const dirClient = new DirectoryClient(bootstrapCircuit, { timeoutMs: 600_000 });

  let lastProgress: DownloadProgress | null = null;
  let progressCount = 0;
  const startTime = Date.now();
  let lastDataTime = Date.now();

  const onProgress = (progress: DownloadProgress) => {
    progressCount++;
    lastProgress = progress;
    const now = Date.now();
    const elapsed = ((now - startTime) / 1000).toFixed(1);
    const sinceLastData = now - lastDataTime;
    lastDataTime = now;
    const speed = (progress.speedBytesPerSec / 1024).toFixed(1);
    const downloaded = (progress.bytesReceived / 1024).toFixed(1);
    const eta = progress.estimatedRemainingMs
      ? (progress.estimatedRemainingMs / 1000).toFixed(0)
      : '?';

    console.log(
      `[progress #${progressCount}] ${elapsed}s: ${downloaded} KB @ ${speed} KB/s, gap=${sinceLastData}ms, ETA: ${eta}s`
    );
  };

  // Watchdog to detect stalls
  const stallCheckInterval = setInterval(() => {
    const now = Date.now();
    const stallTime = now - lastDataTime;
    if (stallTime > 5000) {
      console.log(`[STALL DETECTED] No data for ${(stallTime / 1000).toFixed(1)}s`);
    }
  }, 5000);

  try {
    const consensus = await dirClient.downloadMicrodescConsensus(onProgress);
    clearInterval(stallCheckInterval);
    const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[test] Download complete in ${totalTime}s`);
    console.log(`[test] Consensus size: ${(consensus.length / 1024).toFixed(1)} KB`);
    console.log(`[test] Total progress events: ${progressCount}`);

    t.true(consensus.length > 100_000, 'Consensus should be > 100KB');
    t.true(progressCount > 5, 'Should have multiple progress events');
  } catch (error) {
    clearInterval(stallCheckInterval);
    console.error('[test] Download failed:', error);
    console.log(`[test] Last progress: ${JSON.stringify(lastProgress)}`);
    console.log(`[test] Progress events before failure: ${progressCount}`);
    t.fail(`Download failed: ${error}`);
  } finally {
    bootstrapCircuit.destroy();
    channel.destroy();
  }
});
