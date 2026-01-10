/**
 * Browser-compatible directory functions with CORS proxy support.
 * Wraps the tor package directory functions to work in browsers.
 */

import type { PeerInfo } from 'tor/circuit';
import {
  parseRelaysFromMicroDesc,
  microDescNodeInfoToPeerInfo,
} from 'tor/build-circuit/directory';
import type { MicroDescNodeInfo } from 'tor/build-circuit/directory';

export { pickRelayWithFlags } from 'tor/build-circuit/util';
export type { MicroDescNodeInfo } from 'tor/build-circuit/directory';

/**
 * CORS proxy configuration.
 * Uses allorigins.win as a reliable CORS proxy service.
 */
const DEFAULT_CORS_PROXY = 'https://api.allorigins.win/raw?url=';

export type BrowserDirectoryOptions = {
  corsProxy?: string;
};

/**
 * Get a random directory authority from Onionoo (which has CORS support).
 */
export async function getRandomDirectoryAuthorityBrowser(): Promise<{ dir_address: string }> {
  const response = await fetch(
    'https://onionoo.torproject.org/details?limit=30&running=true&search=flag:Authority&order=-consensus_weight',
    {
      headers: {
        accept: 'application/json',
        'user-agent': 'tor-ts-browser',
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Onionoo request failed: ${response.status}`);
  }

  const data = (await response.json()) as { relays: Array<{ dir_address?: string }> };
  const candidates = data.relays.filter(
    (r) => typeof r.dir_address === 'string' && r.dir_address.length > 0
  );

  if (candidates.length === 0) {
    throw new Error('No directory authorities found');
  }

  const selected = candidates[Math.floor(Math.random() * candidates.length)]!;
  return { dir_address: selected.dir_address! };
}

/**
 * Build proxied URL for CORS bypass.
 */
function buildProxiedUrl(directoryServer: string, path: string, options: BrowserDirectoryOptions = {}): string {
  const corsProxy = options.corsProxy ?? DEFAULT_CORS_PROXY;
  const fullUrl = `http://${directoryServer}${path}`;
  return `${corsProxy}${encodeURIComponent(fullUrl)}`;
}

/**
 * Download microdesc consensus via CORS proxy.
 */
export async function downloadMicrodescBrowser(
  directoryServer: string,
  options: BrowserDirectoryOptions = {}
): Promise<string> {
  const url = buildProxiedUrl(directoryServer, '/tor/status-vote/current/consensus-microdesc', options);

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download microdesc: ${response.status}`);
  }

  return response.text();
}

/**
 * Download relay server descriptor via CORS proxy.
 */
async function downloadRelayDescriptorBrowser(
  directoryServer: string,
  rsaIdDigest: Buffer,
  options: BrowserDirectoryOptions = {}
): Promise<string> {
  const fp = rsaIdDigest.toString('hex').toUpperCase();
  const url = buildProxiedUrl(directoryServer, `/tor/server/fp/${fp}`, options);

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download relay descriptor: ${response.status}`);
  }

  return response.text();
}

function extractNtorOnionKey(directoryRecord: string): string {
  const linePrefix = 'ntor-onion-key ';
  const line = directoryRecord.split('\n').find((l) => l.startsWith(linePrefix));
  if (!line) throw new Error('no ntor-onion-key line found');
  return line.slice(linePrefix.length);
}

/**
 * Look up peer info for a relay via CORS proxy.
 */
export async function lookupPeerInfoBrowser(
  directoryServer: string,
  nodeInfo: MicroDescNodeInfo,
  options: BrowserDirectoryOptions = {}
): Promise<PeerInfo> {
  const directoryRecord = await downloadRelayDescriptorBrowser(
    directoryServer,
    nodeInfo.rsaIdDigest,
    options
  );
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord);
  const onionKey = Buffer.from(ntorOnionKeyText, 'base64');
  return microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
}

/**
 * Parse relays from microdesc content.
 */
export { parseRelaysFromMicroDesc };
