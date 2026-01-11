/**
 * Script to update fallback directories from the Tor Project.
 *
 * Usage (from packages/tor):
 *   yarn update:fallback-dirs
 *
 * This fetches the latest fallback_dirs.inc from the Tor GitLab and
 * generates a JSON file that can be imported in Node.js and browsers.
 *
 * Source:
 *   https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FALLBACK_DIRS_URL =
  'https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc';

type FallbackDirEntry = {
  ip: string;
  orPort: number;
  rsaIdHex: string;
  ipv6?: string;
  ipv6Port?: number;
  nickname?: string;
};

type FallbackDirsData = {
  version: string;
  timestamp: string;
  source: string;
  generatedAt: string;
  entries: FallbackDirEntry[];
};

/**
 * Parse the fallback_dirs.inc file format.
 *
 * Format:
 *   "IP orport=PORT id=RSAHEX"
 *   " ipv6=[IPV6]:PORT"  (optional, on next line)
 *   /* nickname=NAME *\/
 */
function parseFallbackDirsInc(content: string): {
  entries: FallbackDirEntry[];
  version?: string;
  timestamp?: string;
} {
  const entries: FallbackDirEntry[] = [];
  let version: string | undefined;
  let timestamp: string | undefined;

  // Extract metadata from comments at top
  const versionMatch = content.match(/\/\*\s*version=([^\s*]+)\s*\*\//);
  if (versionMatch) version = versionMatch[1];

  const timestampMatch = content.match(/\/\*\s*timestamp=(\d+)\s*\*\//);
  if (timestampMatch) timestamp = timestampMatch[1];

  // Split into entry blocks (separated by commas)
  const lines = content.split('\n');

  let currentEntry: Partial<FallbackDirEntry> | null = null;

  for (const line of lines) {
    const trimmed = line.trim();

    // Main entry line: "IP orport=PORT id=RSAHEX"
    const mainMatch = trimmed.match(/^"(\d+\.\d+\.\d+\.\d+)\s+orport=(\d+)\s+id=([A-F0-9]+)"/i);
    if (mainMatch) {
      // Save previous entry if exists
      if (currentEntry?.ip && currentEntry?.orPort && currentEntry?.rsaIdHex) {
        entries.push(currentEntry as FallbackDirEntry);
      }
      currentEntry = {
        ip: mainMatch[1],
        orPort: parseInt(mainMatch[2]!, 10),
        rsaIdHex: mainMatch[3]!.toUpperCase(),
      };
      continue;
    }

    // IPv6 line: " ipv6=[IPV6]:PORT"
    const ipv6Match = trimmed.match(/^"\s*ipv6=\[([^\]]+)\]:(\d+)"/);
    if (ipv6Match && currentEntry) {
      currentEntry.ipv6 = ipv6Match[1];
      currentEntry.ipv6Port = parseInt(ipv6Match[2]!, 10);
      continue;
    }

    // Nickname comment: /* nickname=NAME */
    const nicknameMatch = trimmed.match(/\/\*\s*nickname=(\S+)\s*\*\//);
    if (nicknameMatch && currentEntry) {
      currentEntry.nickname = nicknameMatch[1];
      continue;
    }
  }

  // Don't forget the last entry
  if (currentEntry?.ip && currentEntry?.orPort && currentEntry?.rsaIdHex) {
    entries.push(currentEntry as FallbackDirEntry);
  }

  return { entries, version, timestamp };
}

async function main() {
  console.log('Fetching fallback_dirs.inc from Tor Project...');
  console.log(`  URL: ${FALLBACK_DIRS_URL}`);

  const response = await fetch(FALLBACK_DIRS_URL);
  if (!response.ok) {
    throw new Error(`Failed to fetch: ${response.status} ${response.statusText}`);
  }

  const content = await response.text();
  console.log(`  Downloaded ${content.length} bytes`);

  const { entries, version, timestamp } = parseFallbackDirsInc(content);
  console.log(`  Parsed ${entries.length} fallback directory entries`);

  if (entries.length === 0) {
    throw new Error('No entries parsed - check if format has changed');
  }

  const data: FallbackDirsData = {
    version: version ?? 'unknown',
    timestamp: timestamp ?? 'unknown',
    source: FALLBACK_DIRS_URL,
    generatedAt: new Date().toISOString(),
    entries,
  };

  // Write JSON file
  const outputPath = path.join(__dirname, '..', 'src', 'fallback-dirs.json');
  await fs.writeFile(outputPath, JSON.stringify(data, null, 2) + '\n');
  console.log(`  Written to: ${outputPath}`);

  // Print summary
  console.log('\nSummary:');
  console.log(`  Version: ${data.version}`);
  console.log(`  Timestamp: ${data.timestamp}`);
  console.log(`  Entries: ${entries.length}`);
  console.log(`  With IPv6: ${entries.filter((e) => e.ipv6).length}`);

  // Show first few entries as sample
  console.log('\nSample entries:');
  for (const entry of entries.slice(0, 3)) {
    console.log(`  ${entry.ip}:${entry.orPort} (${entry.nickname ?? 'unnamed'})`);
  }
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
