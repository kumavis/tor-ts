import fs from 'node:fs/promises';
import path from 'node:path';

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { AddressTypes, LinkSpecifierTypes, addressAndPortToLinkSpecifier } from 'tor/messaging';
import type { LinkSpecifier } from 'tor/messaging';

import { SnowflakeTlsChannelConnection } from './tor-channel.ts';

async function discoverDirectoryServerIpPort(): Promise<string> {
  if (process.env.CHUTNEY_DIRECTORY_SERVER) {
    return process.env.CHUTNEY_DIRECTORY_SERVER;
  }

  const dataDir = process.env.CHUTNEY_DATA_DIR;
  if (dataDir) {
    const nodesDir = path.join(dataDir, 'nodes');
    try {
      const entries = await fs.readdir(nodesDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const torrcPath = path.join(nodesDir, entry.name, 'torrc');
        let torrc: string;
        try {
          torrc = await fs.readFile(torrcPath, 'utf8');
        } catch {
          continue;
        }
        const match = torrc.match(/^DirPort\s+(\d+)\b/m);
        if (!match) continue;
        const dirPortText = match[1];
        if (!dirPortText) continue;
        const dirPort = Number.parseInt(dirPortText, 10);
        if (!Number.isFinite(dirPort) || dirPort <= 0) continue;
        return `127.0.0.1:${dirPort}`;
      }
    } catch {
      // fall through
    }
  }

  return '127.0.0.1:7000';
}

// Minimal directory helpers (copied from tor/build-circuit/directory.ts and util.ts) without Onionoo dependency.

type MicroDescNodeInfo = {
  nickname: string;
  rsaIdDigest: Buffer;
  publication_date: Date;
  ip_address: string;
  onion_router_port: number;
  directory_server_port: number;
  mKey?: Buffer;
  flags?: string[];
  version?: string;
  protocols: Record<string, string>;
  bandwidthStats?: Record<string, number>;
};

const fetchWithRetry = async (url: string, opts: RequestInit = {}) => {
  const maxRetries = 3;
  const retryDelay = 500;
  let retries = 0;
  while (true) {
    try {
      const response = await fetch(url, opts);
      if (!response.ok) {
        throw new Error(`Failed to fetch: ${response.status} ${response.statusText}`);
      }
      return response;
    } catch (err) {
      retries++;
      if (retries > maxRetries) throw err;
      await new Promise((resolve) => setTimeout(resolve, retryDelay));
    }
  }
};

async function downloadMicrodescFromDirectory(directoryServerIpPort: string): Promise<string> {
  const url = `http://${directoryServerIpPort}/tor/status-vote/current/consensus-microdesc`;
  const response = await fetchWithRetry(url);
  return response.text();
}

function extractNtorOnionKey(directoryRecord: string): string {
  const linePrefix = 'ntor-onion-key ';
  const line = directoryRecord.split('\n').find((l) => l.startsWith(linePrefix));
  if (!line) throw new Error('no ntor-onion-key line found');
  return line.slice(linePrefix.length);
}

async function dangerouslyLookupOnionKey(peerIpPort: string, rsaIdDigest: Buffer): Promise<Buffer> {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`;
  const response = await fetchWithRetry(url);
  const directoryRecord = await response.text();
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord);
  return Buffer.from(ntorOnionKeyText, 'base64');
}

function parseRelaysFromMicroDesc(microDescContent: string): MicroDescNodeInfo[] {
  const lines = microDescContent.split('\n');
  let relayInfo: MicroDescNodeInfo | undefined;
  const relayInfos: MicroDescNodeInfo[] = [];

  for (const line of lines) {
    const tokens = line.split(' ');
    if (tokens[0] === 'r') {
      const parts = line.split(' ');
      if (parts.length < 8) continue;
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
        onion_router_port: Number.parseInt(onionRouterPort, 10),
        directory_server_port: Number.parseInt(directoryServerPort, 10),
        protocols: {},
      };
      relayInfos.push(created);
      relayInfo = created;
    } else if (tokens[0] === 'm') {
      if (!relayInfo) continue;
      const mKeyBase64 = line.split(' ')[1];
      if (!mKeyBase64) continue;
      relayInfo.mKey = Buffer.from(mKeyBase64, 'base64');
    } else if (tokens[0] === 's') {
      if (!relayInfo) continue;
      relayInfo.flags = line.split(' ').slice(1);
    } else if (tokens[0] === 'v') {
      if (!relayInfo) continue;
      const version = line.split(' ')[1];
      if (!version) continue;
      relayInfo.version = version;
    } else if (tokens[0] === 'pr') {
      if (!relayInfo) continue;
      const current = relayInfo;
      const protocolStrings = line.split(' ').slice(1);
      protocolStrings.forEach((protocolString) => {
        const [protocol, versions] = protocolString.split('=');
        if (protocol && versions) current.protocols[protocol] = versions;
      });
    } else if (tokens[0] === 'w') {
      if (!relayInfo) continue;
      const current = relayInfo;
      current.bandwidthStats = {};
      line
        .split(' ')
        .slice(1)
        .forEach((token) => {
          const [type, value] = token.split('=');
          if (type && value) current.bandwidthStats![type] = Number.parseInt(value, 10);
        });
    }
  }

  return relayInfos;
}

function filterRelaysByFlags(
  relays: MicroDescNodeInfo[],
  flags: string[],
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo[] {
  return relays.filter((relayInfo) => {
    const relayFlags = relayInfo.flags ?? [];
    const flagMatches = flags.every((flag) => relayFlags.includes(flag));
    if (!flagMatches) return false;
    const isIgnored = ignoreList.find((ignored) => {
      return ignored === relayInfo || ignored.rsaIdDigest.equals(relayInfo.rsaIdDigest);
    });
    return !isIgnored;
  });
}

function pickRelayWithFlags(
  relays: MicroDescNodeInfo[],
  flags: string[],
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo {
  const matchingRelays = filterRelaysByFlags(relays, flags, ignoreList);
  if (matchingRelays.length === 0) {
    throw new Error(
      `Failed to find any matching relays for [${flags}] from ${relays.length} relays`
    );
  }
  const randomIndex = Math.floor(Math.random() * matchingRelays.length);
  const picked = matchingRelays[randomIndex];
  if (!picked) {
    throw new Error(
      `Failed to pick a relay (index=${randomIndex} length=${matchingRelays.length})`
    );
  }
  return picked;
}

function microDescNodeInfoToPeerInfo(nodeInfo: MicroDescNodeInfo, onionKey: Buffer): PeerInfo {
  const linkSpecifiers: Array<LinkSpecifier> = [];
  linkSpecifiers.push(
    addressAndPortToLinkSpecifier({
      type: AddressTypes.IPv4,
      ip: nodeInfo.ip_address,
      port: nodeInfo.onion_router_port,
    })
  );
  linkSpecifiers.push({ type: LinkSpecifierTypes.LegacyId, data: nodeInfo.rsaIdDigest });
  return {
    onionKey,
    rsaIdDigest: nodeInfo.rsaIdDigest,
    linkSpecifiers,
  };
}

async function dangerouslyLookupPeerInfo(
  directoryServer: string,
  nodeInfo: MicroDescNodeInfo
): Promise<PeerInfo> {
  const onionKey = await dangerouslyLookupOnionKey(directoryServer, nodeInfo.rsaIdDigest);
  return microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
}

export async function connectSnowflakeChutneyCircuit(opts: {
  relayUrl: string;
  expectedEntryOrPort?: number;
}): Promise<Circuit> {
  const directoryServer = await discoverDirectoryServerIpPort();
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: opts.relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  const entryOnionKey = await dangerouslyLookupOnionKey(directoryServer, entryRsaIdDigest);
  const entryPeerInfo: PeerInfo = {
    onionKey: entryOnionKey,
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [{ type: LinkSpecifierTypes.LegacyId, data: entryRsaIdDigest }],
  };

  if (opts.expectedEntryOrPort) {
    const match = microDescNodeInfos.find((n) => n.rsaIdDigest.equals(entryRsaIdDigest));
    if (match && match.onion_router_port !== opts.expectedEntryOrPort) {
      throw new Error(
        `snowflake entry ORPort mismatch: expected ${opts.expectedEntryOrPort} got ${match.onion_router_port}`
      );
    }
  }

  const ignoreEntry = [{ rsaIdDigest: entryRsaIdDigest } as MicroDescNodeInfo];

  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  const exitNode = forcedExitRsaIdDigestHex
    ? (() => {
        const forcedExit = microDescNodeInfos.find((n) => {
          const digestHex = n.rsaIdDigest.toString('hex');
          return digestHex === forcedExitRsaIdDigestHex;
        });
        if (!forcedExit) {
          throw new Error(
            `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
          );
        }
        return forcedExit;
      })()
    : pickRelayWithFlags(microDescNodeInfos, ['Exit'], ignoreEntry);

  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], [exitNode, ...ignoreEntry]);
  const middlePeerInfo = await dangerouslyLookupPeerInfo(directoryServer, middleNode);
  const exitPeerInfo = await dangerouslyLookupPeerInfo(directoryServer, exitNode);

  const pathInfos: PeerInfo[] = [entryPeerInfo, middlePeerInfo, exitPeerInfo];
  const circuit = new Circuit({ path: pathInfos, channel });
  await circuit.connect();
  return circuit;
}
