import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import test from 'ava';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { AddressTypes, LinkSpecifierTypes, addressAndPortToLinkSpecifier } from 'tor/messaging';
import type { LinkSpecifier } from 'tor/messaging';
import { getTorAgentForUrl } from 'tor/node';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

type DirectoryAuthority = { address: string; orPort: number; dirPort?: number };

const liveTest = isLiveEnabled() && isFetchEnabled() ? test.serial : test.serial.skip;

liveTest('snowflake live: build circuit + fetch ipify (optional)', async (t) => {
  t.timeout(180_000);

  const authorities = await loadDirectoryAuthoritiesFromTorPackage();
  const authority = pickRandom(authorities);
  const directoryServer = `${authority.address}:${authority.dirPort ?? authority.orPort}`;

  const microDescContent = await downloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });
  t.teardown(() => channel.destroy());

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  const entryNode = microDescNodeInfos.find((n) => n.rsaIdDigest.equals(entryRsaIdDigest));
  const entryOnionKey = entryNode?.mKey
    ? await dangerouslyLookupOnionKeyByMicrodescDigest(directoryServer, entryNode.mKey)
    : await dangerouslyLookupOnionKeyByServerDescriptor(directoryServer, entryRsaIdDigest);
  const entryPeerInfo: PeerInfo = {
    onionKey: entryOnionKey,
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [{ type: LinkSpecifierTypes.LegacyId, data: entryRsaIdDigest }],
  };

  const ignoreEntry = [{ rsaIdDigest: entryRsaIdDigest } as MicroDescNodeInfo];
  const exitNode = pickRelayWithFlags(microDescNodeInfos, ['Exit'], ignoreEntry);
  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], [exitNode, ...ignoreEntry]);

  const middlePeerInfo = await dangerouslyLookupPeerInfo(directoryServer, middleNode);
  const exitPeerInfo = await dangerouslyLookupPeerInfo(directoryServer, exitNode);

  const circuit = new Circuit({ path: [entryPeerInfo, middlePeerInfo, exitPeerInfo], channel });
  await circuit.connect();
  t.teardown(() => circuit.destroy());

  const url = new URL('https://api.ipify.org?format=json');
  const agent = getTorAgentForUrl(circuit, url.toString());

  const body = await new Promise<string>((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(
      url,
      {
        method: 'GET',
        headers: { accept: 'application/json' },
        agent,
      },
      (res) => {
        let s = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (s += chunk));
        res.on('end', () => resolve(s));
      }
    );
    req.on('error', reject);
    req.end();
  });

  t.regex(body, /"ip"\\s*:\\s*"/);
});

function isLiveEnabled(): boolean {
  const v = process.env.SNOWFLAKE_LIVE?.toLowerCase();
  return v === '1' || v === 'true';
}

function isFetchEnabled(): boolean {
  const v = process.env.SNOWFLAKE_LIVE_FETCH?.toLowerCase();
  return v === '1' || v === 'true';
}

async function loadDirectoryAuthoritiesFromTorPackage(): Promise<DirectoryAuthority[]> {
  // NOTE: This is test-only wiring inside this monorepo; not part of snowflake's runtime API.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const authoritiesPath = path.resolve(here, '../../../tor/src/directory-authorities.json');
  const text = await fs.readFile(authoritiesPath, 'utf8');
  const json = JSON.parse(text) as unknown;

  if (!Array.isArray(json)) throw new Error('unexpected directory-authorities.json shape');

  const out: DirectoryAuthority[] = [];
  for (const item of json) {
    if (!item || typeof item !== 'object') continue;
    const it = item as Record<string, unknown>;
    const dirAddress = typeof it.dir_address === 'string' ? it.dir_address : undefined;
    const orAddresses = Array.isArray(it.or_addresses)
      ? it.or_addresses.filter((x) => typeof x === 'string')
      : [];

    // Prefer the directory port, since we're going to fetch the microdesc/descriptor over HTTP.
    const ipPort = dirAddress ?? (orAddresses[0] as string | undefined);
    if (!ipPort) continue;

    // Accept both IPv4 "ip:port" and bracketed IPv6 "[...]:port".
    const parsed = parseIpPort(ipPort);
    if (!parsed) continue;

    const dirPort = dirAddress ? parsed.port : undefined;
    const orPort = dirAddress ? 0 : parsed.port;
    out.push(
      dirPort === undefined
        ? { address: parsed.address, orPort }
        : { address: parsed.address, orPort, dirPort }
    );
  }

  if (out.length === 0) throw new Error('no directory authorities loaded');
  return out;
}

function parseIpPort(ipPort: string): { address: string; port: number } | null {
  const s = ipPort.trim();
  // [IPv6]:port
  if (s.startsWith('[')) {
    const idx = s.lastIndexOf(']:');
    if (idx === -1) return null;
    const host = s.slice(1, idx);
    const portText = s.slice(idx + 2);
    const port = Number.parseInt(portText, 10);
    if (!host || !Number.isFinite(port) || port <= 0) return null;
    return { address: host, port };
  }
  // IPv4:port (or hostname:port)
  const idx = s.lastIndexOf(':');
  if (idx === -1) return null;
  const host = s.slice(0, idx);
  const portText = s.slice(idx + 1);
  const port = Number.parseInt(portText, 10);
  if (!host || !Number.isFinite(port) || port <= 0) return null;
  return { address: host, port };
}

function pickRandom<T>(arr: readonly T[]): T {
  if (arr.length === 0) throw new Error('pickRandom: empty array');
  return arr[Math.floor(Math.random() * arr.length)]!;
}

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
  const line = directoryRecord.split('\\n').find((l) => l.startsWith(linePrefix));
  if (!line) throw new Error('no ntor-onion-key line found');
  return line.slice(linePrefix.length);
}

async function dangerouslyLookupOnionKeyByServerDescriptor(
  peerIpPort: string,
  rsaIdDigest: Buffer
): Promise<Buffer> {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`;
  const response = await fetchWithRetry(url);
  const directoryRecord = await response.text();
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord);
  return Buffer.from(ntorOnionKeyText, 'base64');
}

async function dangerouslyLookupOnionKeyByMicrodescDigest(
  peerIpPort: string,
  microdescDigest: Buffer
): Promise<Buffer> {
  // Dir-spec: /tor/micro/d/<hex-encoded microdesc digests...>
  const url = `http://${peerIpPort}/tor/micro/d/${microdescDigest.toString('hex').toUpperCase()}`;
  const response = await fetchWithRetry(url);
  const microdescText = await response.text();
  const ntorOnionKeyText = extractNtorOnionKey(microdescText);
  return Buffer.from(ntorOnionKeyText, 'base64');
}

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

function parseRelaysFromMicroDesc(microDescContent: string): MicroDescNodeInfo[] {
  const lines = microDescContent.split('\\n');
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
  const onionKey = nodeInfo.mKey
    ? await dangerouslyLookupOnionKeyByMicrodescDigest(directoryServer, nodeInfo.mKey)
    : await dangerouslyLookupOnionKeyByServerDescriptor(directoryServer, nodeInfo.rsaIdDigest);
  return microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
}
