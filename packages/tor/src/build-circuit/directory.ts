/**
 * Directory lookup utilities for Tor circuit building.
 *
 * ## WARNING: "Dangerous" Methods
 *
 * Several functions in this module are prefixed with "dangerously" because they
 * make **direct HTTP requests** to directory servers, bypassing Tor circuits.
 * This leaks the client's IP address and request patterns to:
 *
 * 1. The directory server
 * 2. Any network observer between the client and server
 *
 * ### Safe Bootstrap (Recommended)
 *
 * The Tor spec provides a safe bootstrap mechanism using hardcoded fallback
 * directories (see `fallback-dirs.ts` and `mainnet.ts`):
 *
 * ```typescript
 * import { mainnet } from 'tor';
 *
 * // Safe bootstrap: connects via TLS to fallback, uses RELAY_BEGIN_DIR
 * const circuit = await mainnet.connectRandomCircuitWithSafeBootstrap();
 * ```
 *
 * This is safer because:
 * - Connection is encrypted (TLS + Tor encryption)
 * - Relay identity is cryptographically verified
 * - Traffic looks like normal Tor (not HTTP)
 * - Directory request content is hidden from network observers
 *
 * ### When Dangerous Methods Are Still Used
 *
 * - **Testing/Development**: In controlled test environments like Chutney,
 *   privacy isn't a concern and direct fetches are simpler.
 *
 * - **Legacy Code**: Some code paths still use dangerous methods for
 *   backwards compatibility. These are marked `@deprecated`.
 *
 * ### Safe Alternatives
 *
 * After you have at least one circuit, use the safe alternatives in
 * `directory-client.ts`:
 *
 * - `DirectoryClient` - Make directory requests through circuit streams
 * - `lookupPeerInfo()` - Safe equivalent of `dangerouslyLookupPeerInfo()`
 * - `lookupPeerInfoWithEd25519IdentityKey()` - Safe equivalent
 *
 * @see {@link ../fallback-dirs.ts} for hardcoded fallback directories
 * @see {@link ../directory-client.ts} for safe directory lookups
 * @see {@link ./mainnet.ts#connectRandomCircuitWithSafeBootstrap} for safe bootstrap
 */

import type { PeerInfo } from '../circuit.ts';
import { AddressTypes, LinkSpecifierTypes, addressAndPortToLinkSpecifier } from '../messaging.ts';
import type { LinkSpecifier } from '../messaging.ts';

export type DirectoryAuthority = {
  dir_address?: string;
};

type OnionooDetailsResponse = {
  relays: Array<DirectoryAuthority>;
};

type DangerouslyFetchWithRetryOptions = RequestInit & {
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
};

const onionooCache = {
  relays: [] as Array<DirectoryAuthority>,
  expiresAtMs: 0,
};

export async function getRandomDirectoryAuthority(): Promise<DirectoryAuthority> {
  const response = await dangerouslyFetchOnionooDetailsWithCache({
    limit: '30',
    running: 'true',
    search: 'flag:Authority',
    order: '-consensus_weight',
  });

  const candidates = response.relays.filter(
    (r) => typeof r.dir_address === 'string' && r.dir_address.length > 0
  );
  if (candidates.length === 0) {
    throw new Error('No directory authorities returned from Onionoo (missing dir_address)');
  }

  const selected = candidates[Math.floor(Math.random() * candidates.length)];
  if (!selected) throw new Error('Failed to select a directory authority');
  return selected;
}

async function dangerouslyFetchOnionooDetailsWithCache(
  query: Record<string, string>
): Promise<OnionooDetailsResponse> {
  const now = Date.now();
  if (onionooCache.expiresAtMs > now && onionooCache.relays.length > 0) {
    return { relays: onionooCache.relays };
  }

  const u = new URL('https://onionoo.torproject.org/details');
  u.search = new URLSearchParams(query).toString();
  const res = await dangerouslyFetchWithRetry(u.toString(), {
    timeoutMs: 12_000,
    maxRetries: 5,
    retryDelayMs: 750,
    headers: {
      accept: 'application/json',
      // Identify as a script without leaking a stable, unique identifier.
      'user-agent': 'tor-ts (build-circuit)',
    },
  });
  const json = (await res.json()) as unknown;
  if (!json || typeof json !== 'object') throw new Error('Onionoo response was not an object');
  const obj = json as Record<string, unknown>;

  const relays = Array.isArray(obj.relays) ? (obj.relays as Array<DirectoryAuthority>) : [];
  onionooCache.relays = relays;
  onionooCache.expiresAtMs = now + 5 * 60_000;
  return { relays };
}

// perform fetch with retry and delay
const dangerouslyFetchWithRetry = async (
  url: string,
  opts: DangerouslyFetchWithRetryOptions = {}
) => {
  const maxRetries = opts.maxRetries ?? 3;
  const retryDelayMs = opts.retryDelayMs ?? 500;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    timeout.unref?.();

    try {
      const { timeoutMs: _t, maxRetries: _m, retryDelayMs: _r, ...fetchOpts } = opts;
      const response = await fetch(url, { ...fetchOpts, signal: controller.signal });
      if (!response.ok) {
        throw new Error(`Fetch failed for ${url}: ${response.status} ${response.statusText}`);
      }
      return response;
    } catch (err) {
      lastErr = err;
      if (attempt >= maxRetries) break;
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastErr instanceof Error ? lastErr : new Error(`Fetch failed for ${url}`);
};

/**
 * Look up a relay's ntor-onion-key by making a direct HTTP request.
 *
 * ⚠️ **DANGEROUS**: This makes a direct HTTP request, leaking your IP.
 * Use only for initial bootstrap. For subsequent lookups, use `lookupOnionKey()`
 * from `directory-client.ts` with an existing circuit.
 *
 * @see {@link ../directory-client.ts#lookupOnionKey} for the safe alternative
 */
export async function dangerouslyLookupOnionKey(peerIpPort: string, rsaIdDigest: Buffer) {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`;
  const response = await dangerouslyFetchWithRetry(url);
  if (!response.ok) {
    throw new Error(
      `Failed to query peer for onion key: ${response.status} ${response.statusText}`
    );
  }
  const directoryRecord = await response.text();
  // console.log('fp lookup:', directoryRecord)
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord);
  // console.log('dangerouslyLookupOnionKey', ntorOnionKeyText)
  const ntorOnionKey = Buffer.from(ntorOnionKeyText, 'base64');
  return ntorOnionKey;
}

/**
 * Download the consensus-microdesc document via direct HTTP request.
 *
 * ⚠️ **DANGEROUS**: This makes a direct HTTP request, leaking your IP.
 * Use only for initial bootstrap. For subsequent downloads, use
 * `DirectoryClient.downloadMicrodescConsensus()` with an existing circuit.
 *
 * @see {@link ../directory-client.ts#DirectoryClient.downloadMicrodescConsensus} for the safe alternative
 */
export async function dangerouslyDownloadMicrodescFromDirectory(
  directoryServerIpPort: string
): Promise<string> {
  const url = `http://${directoryServerIpPort}/tor/status-vote/current/consensus-microdesc`;
  const response = await dangerouslyFetchWithRetry(url);
  if (!response.ok) {
    throw new Error(
      `Failed to query directory for microdesc: ${response.status} ${response.statusText}`
    );
  }
  const directoryRecord = await response.text();
  // console.log('microdesc lookup:', directoryRecord)
  return directoryRecord;
}

function extractNtorOnionKey(directoryRecord: string): string {
  // ntor-onion-key RrV6Ae3gauyxgdTiIYvcRqJepNrAa4r2Fh8s0JI02wA
  const linePrefix = 'ntor-onion-key ';
  const line = directoryRecord.split('\n').find((line) => line.startsWith(linePrefix));
  if (!line) throw new Error('no ntor-onion-key line found');
  const ntorOnionKey = line.slice(linePrefix.length);
  return ntorOnionKey;
}

function extractMasterKeyEd25519(directoryRecord: string): string {
  // master-key-ed25519 g+QcBzNGERaiCl2KJbCyob0B8rlynPBSMlkJKprMzfU
  const linePrefix = 'master-key-ed25519 ';
  const line = directoryRecord.split('\n').find((line) => line.startsWith(linePrefix));
  if (!line) throw new Error('no master-key-ed25519 line found');
  return line.slice(linePrefix.length).trim();
}

/**
 * Download a relay's full server descriptor via direct HTTP request.
 *
 * ⚠️ **DANGEROUS**: This makes a direct HTTP request, leaking your IP.
 * Use only for initial bootstrap. For subsequent downloads, use
 * `DirectoryClient.downloadRelayServerDescriptor()` with an existing circuit.
 *
 * @see {@link ../directory-client.ts#DirectoryClient.downloadRelayServerDescriptor} for the safe alternative
 */
async function dangerouslyDownloadRelayServerDescriptor(
  peerIpPort: string,
  rsaIdDigest: Buffer
): Promise<string> {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`;
  const response = await dangerouslyFetchWithRetry(url);
  if (!response.ok) {
    throw new Error(
      `Failed to query peer for relay descriptor: ${response.status} ${response.statusText}`
    );
  }
  return await response.text();
}

export type MicroDescNodeInfo = {
  nickname: string;
  rsaIdDigest: Buffer;
  publication_date: Date;
  ip_address: string;
  onion_router_port: number;
  directory_server_port: number;
  // idk what this is
  mKey?: Buffer;
  flags?: string[];
  version?: string;
  protocols: Record<string, string>;
  // bandwidth?: number;
  // unmeasured?: number;
  bandwidthStats?: Record<string, number>;
};

export type MicroDescConsensus = {
  validAfter: Date | undefined;
  freshUntil: Date | undefined;
  validUntil: Date | undefined;
  params: Record<string, number>;
  sharedRandPreviousValue: Buffer | undefined;
  sharedRandCurrentValue: Buffer | undefined;
  relays: MicroDescNodeInfo[];
};

export function parseRelaysFromMicroDesc(microDescContent: string): MicroDescNodeInfo[] {
  return parseMicroDescConsensus(microDescContent).relays;
}

export function parseMicroDescConsensus(microDescContent: string): MicroDescConsensus {
  const lines = microDescContent.split('\n');
  let relayInfo: MicroDescNodeInfo | undefined;
  const relayInfos: MicroDescNodeInfo[] = [];
  const params: Record<string, number> = {};
  let validAfter: Date | undefined;
  let freshUntil: Date | undefined;
  let validUntil: Date | undefined;
  let sharedRandPreviousValue: Buffer | undefined;
  let sharedRandCurrentValue: Buffer | undefined;

  // r test002a AB+0S6hvSEnm7ifzqh3QaYOxsm0 2038-01-01 00:00:00 127.0.0.1 5002 7002
  // m BY6mSHVSthDKuKGu8aiGKhuGkwZqJqDLs9RxY99gKYs
  // s Authority Exit Fast Guard HSDir Running Stable V2Dir Valid
  // v Tor 0.4.8.1-alpha-dev
  // pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
  // w Bandwidth=158 Unmeasured=1

  for (const line of lines) {
    const tokens = line.split(' ');
    if (tokens[0] === 'valid-after') {
      const d = tokens[1];
      const t = tokens[2];
      if (d && t) validAfter = new Date(`${d} ${t} UTC`);
      continue;
    } else if (tokens[0] === 'fresh-until') {
      const d = tokens[1];
      const t = tokens[2];
      if (d && t) freshUntil = new Date(`${d} ${t} UTC`);
      continue;
    } else if (tokens[0] === 'valid-until') {
      const d = tokens[1];
      const t = tokens[2];
      if (d && t) validUntil = new Date(`${d} ${t} UTC`);
      continue;
    } else if (tokens[0] === 'params') {
      // Example: params bwweightscale=10000 hsdir-interval=1440 ...
      for (const kv of tokens.slice(1)) {
        const [k, v] = kv.split('=');
        if (!k || !v) continue;
        const n = Number.parseInt(v, 10);
        if (!Number.isFinite(n)) continue;
        params[k] = n;
      }
      continue;
    } else if (tokens[0] === 'shared-rand-previous-value') {
      // shared-rand-previous-value <NUM_REVEALS> <BASE64>
      const valueB64 = tokens[2];
      if (valueB64) sharedRandPreviousValue = Buffer.from(valueB64, 'base64');
      continue;
    } else if (tokens[0] === 'shared-rand-current-value') {
      const valueB64 = tokens[2];
      if (valueB64) sharedRandCurrentValue = Buffer.from(valueB64, 'base64');
      continue;
    }

    if (tokens[0] === 'r') {
      const parts = line.split(' ');
      if (parts.length < 8) {
        continue;
      }
      const nickname = parts[1];
      const rsaIdDigestBase64 = parts[2];
      const publicationDate = parts[3];
      const publicationTime = parts[4];
      const ipAddress = parts[5];
      const onionRouterPort = parts[6];
      const directoryServerPort = parts[7];
      if (
        !nickname ||
        !rsaIdDigestBase64 ||
        !publicationDate ||
        !publicationTime ||
        !ipAddress ||
        !onionRouterPort ||
        !directoryServerPort
      ) {
        continue;
      }
      const created: MicroDescNodeInfo = {
        nickname,
        rsaIdDigest: Buffer.from(rsaIdDigestBase64, 'base64'),
        publication_date: new Date(`${publicationDate} ${publicationTime}`),
        ip_address: ipAddress,
        onion_router_port: parseInt(onionRouterPort, 10),
        directory_server_port: parseInt(directoryServerPort, 10),
        protocols: {},
      };
      relayInfos.push(created);
      relayInfo = created;
    } else if (tokens[0] === 'm') {
      if (!relayInfo) continue;
      const parts = line.split(' ');
      const mKeyBase64 = parts[1];
      if (!mKeyBase64) continue;
      relayInfo.mKey = Buffer.from(mKeyBase64, 'base64');
    } else if (tokens[0] === 's') {
      if (!relayInfo) continue;
      const parts = line.split(' ');
      relayInfo.flags = parts.slice(1);
    } else if (tokens[0] === 'v') {
      if (!relayInfo) continue;
      const parts = line.split(' ');
      const version = parts[1];
      if (!version) continue;
      relayInfo.version = version;
    } else if (tokens[0] === 'pr') {
      if (!relayInfo) continue;
      const currentRelayInfo = relayInfo;
      const parts = line.split(' ');
      const protocolStrings = parts.slice(1);
      protocolStrings.forEach((protocolString) => {
        const [protocol, versions] = protocolString.split('=');
        if (protocol && versions) {
          currentRelayInfo.protocols[protocol] = versions;
        }
      });
    } else if (tokens[0] === 'w') {
      if (!relayInfo) continue;
      const currentRelayInfo = relayInfo;
      const parts = line.split(' ');
      currentRelayInfo.bandwidthStats = {};
      // w Bandwidth=82000 Unmeasured=1
      parts.slice(1).forEach((token) => {
        const [type, value] = token.split('=');
        if (type && value) {
          currentRelayInfo.bandwidthStats![type] = parseInt(value);
        }
      });
    }
  }

  return {
    validAfter,
    freshUntil,
    validUntil,
    params,
    sharedRandPreviousValue,
    sharedRandCurrentValue,
    relays: relayInfos,
  };
}

/**
 * Look up PeerInfo for a relay by making direct HTTP requests.
 *
 * ⚠️ **DANGEROUS**: This makes direct HTTP requests, leaking your IP.
 * Use only for initial bootstrap. For subsequent lookups, use
 * `lookupPeerInfo()` from `directory-client.ts` with an existing circuit.
 *
 * @see {@link ../directory-client.ts#lookupPeerInfo} for the safe alternative
 */
export async function dangerouslyLookupPeerInfo(
  directoryServer: string,
  nodeInfo: MicroDescNodeInfo
) {
  const { peerInfo } = await dangerouslyLookupPeerInfoWithEd25519IdentityKey(
    directoryServer,
    nodeInfo
  );
  return peerInfo;
}

/**
 * Look up PeerInfo with Ed25519 identity by making direct HTTP requests.
 *
 * ⚠️ **DANGEROUS**: This makes direct HTTP requests, leaking your IP.
 * Use only for initial bootstrap. For subsequent lookups, use
 * `lookupPeerInfoWithEd25519IdentityKey()` from `directory-client.ts`
 * with an existing circuit.
 *
 * @see {@link ../directory-client.ts#lookupPeerInfoWithEd25519IdentityKey} for the safe alternative
 */
export async function dangerouslyLookupPeerInfoWithEd25519IdentityKey(
  directoryServer: string,
  nodeInfo: MicroDescNodeInfo
): Promise<{ peerInfo: PeerInfo; ed25519IdentityKey: Buffer }> {
  const directoryRecord = await dangerouslyDownloadRelayServerDescriptor(
    directoryServer,
    nodeInfo.rsaIdDigest
  );
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord);
  const onionKey = Buffer.from(ntorOnionKeyText, 'base64');
  const ed25519IdentityKey = Buffer.from(extractMasterKeyEd25519(directoryRecord), 'base64');
  if (ed25519IdentityKey.length !== 32) {
    throw new Error(`Expected 32-byte ed25519 identity, got ${ed25519IdentityKey.length}`);
  }
  const peerInfo = microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
  return { peerInfo, ed25519IdentityKey };
}

export function microDescNodeInfoToPeerInfo(
  nodeInfo: MicroDescNodeInfo,
  onionKey: Buffer
): PeerInfo {
  const linkSpecifiers: Array<LinkSpecifier> = [];
  // For purposes of indistinguishability, implementations SHOULD send
  //  these link specifiers, if using them, in this order:
  // [00], [02], [03], [01].

  // [00] TLS-over-TCP, IPv4 address
  //       A four-byte IPv4 address plus two-byte ORPort
  // [01] TLS-over-TCP, IPv6 address
  //       A sixteen-byte IPv6 address plus two-byte ORPort
  // [02] Legacy identity
  //       A 20-byte SHA1 identity fingerprint. At most one may be listed.
  // [03] Ed25519 identity
  //       A 32-byte Ed25519 identity fingerprint. At most one may
  //       be listed.

  linkSpecifiers.push(
    addressAndPortToLinkSpecifier({
      type: AddressTypes.IPv4,
      ip: nodeInfo.ip_address,
      port: nodeInfo.onion_router_port,
    })
  );
  linkSpecifiers.push({
    type: LinkSpecifierTypes.LegacyId,
    data: nodeInfo.rsaIdDigest,
  });
  // TODO: include ed25519 linkSpecifiers if available
  // Ed25519 identity keys are not required in EXTEND2 cells, so all zero
  //  keys SHOULD be accepted. If the extending relay knows the ed25519 key from
  //  the consensus, it SHOULD also check that key. (See section 5.1.2.)
  // linkSpecifiers.push({
  //   type: LinkSpecifierTypes.Ed25519Id,
  //   data: Buffer.alloc(32),
  // })
  return {
    onionKey,
    rsaIdDigest: nodeInfo.rsaIdDigest,
    linkSpecifiers,
  };
}

// interface MicroDesc {
//     networkStatusVersion: number;
//     voteStatus: string;
//     consensusMethod: number;
//     validAfter: Date;
//     freshUntil: Date;
//     validUntil: Date;
//     votingDelay: number[];
//     clientVersions: string;
//     serverVersions: string;
//     knownFlags: string[];
//     recommendedClientProtocols: Record<string, string>;
//     recommendedRelayProtocols: Record<string, string>;
//     requiredClientProtocols: Record<string, string>;
//     requiredRelayProtocols: Record<string, string>;
//     sharedRandPreviousValue: string;
//     sharedRandCurrentValue: string;
//     dirSource: string[];
//     voteDigest: string;
//     directoryFooter: string;
//     bandwidthWeights: Record<string, number>;
//     directorySignature: string[];
// }

// function parseMicroDesc(content: string): MicroDesc {
//   let lines = content.split("\n");
//   let microDesc: Partial<MicroDesc> = {};

//   lines.forEach((line) => {
//     let tokens = line.split(" ");

//     // switch(tokens[0]) {
//     //   case 'network-status-version':
//     //     microDesc.networkStatusVersion = parseInt(tokens[2]);
//     //     break;
//     //   case 'vote-status':
//     //     microDesc.voteStatus = tokens[1];
//     //     break;
//     //   case 'consensus-method':
//     //     microDesc.consensusMethod = parseInt(tokens[1]);
//     //     break;
//     //   case 'valid-after':
//     //     microDesc.validAfter = new Date(tokens[1] + ' ' + tokens[2]);
//     //     break;
//     //   case 'fresh-until':
//     //     microDesc.freshUntil = new Date(tokens[1] + ' ' + tokens[2]);
//     //     break;
//     //   case 'valid-until':
//     //     microDesc.validUntil = new Date(tokens[1] + ' ' + tokens[2]);
//     //     break;
//     //   case 'voting-delay':
//     //     microDesc.votingDelay = [parseInt(tokens[1]), parseInt(tokens[2])];
//     //     break;
//     //   case 'client-versions':
//     //     microDesc.clientVersions = tokens.slice(1).join(" ");
//     //     break;
//     //   case 'server-versions':
//     //     microDesc.serverVersions = tokens.slice(1).join(" ");
//     //     break;
//     //   case 'known-flags':
//     //     microDesc.knownFlags = tokens.slice(1);
//     //     break;
//     //   case 'recommended-client-protocols':
//     //   case 'recommended-relay-protocols':
//     //   case 'required-client-protocols':
//     //   case 'required-relay-protocols':
//     //     let protocolMap: Record<string, string> = {};
//     //     tokens.slice(1).forEach((token) => {
//     //       let [protocol, version] = token.split('=');
//     //       protocolMap[protocol] = version;
//     //     });
//     //     microDesc[tokens[0]] = protocolMap;
//     //     break;
//     //   case 'shared-rand-previous-value':
//     //   case 'shared-rand-current-value':
//     //     microDesc[tokens[0]] = tokens.slice(2).join(" ");
//     //     break;
//     //   case 'dir-source':
//     //     microDesc.dirSource = tokens.slice(1);
//     //     break;
//     //   case 'vote-digest':
//     //     microDesc.voteDigest = tokens[1];
//     //     break;
//     //   case 'directory-footer':
//     //     microDesc.directoryFooter = tokens[0];
//     //     break;
//     //   case 'bandwidth-weights':
//     //     let bandwidthWeights: Record<string, number> = {};
//     //     tokens.slice(1).forEach((token) => {
//     //       let [weight, value] = token.split('=');
//     //       bandwidthWeights[weight] = parseInt(value);
//     //     });
//     //     microDesc.bandwidthWeights = bandwidthWeights;
//     //     break;
//     //   case 'directory-signature':
//     //     microDesc.directorySignature.push(tokens.slice(2).join(" "));
//     //     break;
//     // }
//   });

//   // if(!microDesc.networkStatusVersion || !microDesc.voteStatus || !microDesc.consensusMethod || !microDesc.validAfter || !microDesc.freshUntil || !microDesc.validUntil || !microDesc.votingDelay || !microDesc.knownFlags || !microDesc.recommendedClientProtocols || !microDesc.recommendedRelayProtocols || !microDesc.requiredClientProtocols || !microDesc.requiredRelayProtocols || !microDesc.sharedRandPreviousValue || !microDesc.sharedRandCurrentValue || !microDesc.dirSource || !microDesc.voteDigest || !microDesc.directoryFooter || !microDesc.bandwidthWeights || !microDesc.directorySignature){
//   //   throw new Error("Parsing failed, not all necessary fields are provided");
//   // }
//   return microDesc as MicroDesc;
// }
