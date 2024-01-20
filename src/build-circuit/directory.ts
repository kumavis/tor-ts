import fs from 'fs';
import Onionoo from 'onionoo';
import * as url from 'node:url';
import { PeerInfo } from '../circuit';
import { AddressTypes, LinkSpecifier, LinkSpecifierTypes, addressAndPortToLinkSpecifier } from '../messaging';
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

// get "consensus document"
// curl `${authority.dir_address}/tor/status-vote/current/consensus`

// get "relay descriptor"
// curl `${relay.dir_address}/tor/server/fp/${relay.fingerprint}`

// {
//   nickname: 'dizum',
//   fingerprint: '7EA6EAD6FD83083C538F44038BBFA077587DD755',
//   or_addresses: [ '45.66.33.45:443' ],
//   dir_address: '45.66.33.45:80',
//   last_seen: '2023-06-01 08:00:00',
//   last_changed_address_or_port: '2019-08-12 16:00:00',
//   first_seen: '2007-10-27 12:00:00',
//   running: true,
//   flags: [ 'Authority', 'Fast', 'Running', 'Stable', 'V2Dir', 'Valid' ],
//   country: 'nl',
//   country_name: 'Netherlands',
//   as: 'AS47482',
//   as_name: 'Spectre Operations B.V.',
//   consensus_weight: 20,
//   verified_host_names: [ 'tor.dizum.com' ],
//   last_restarted: '2023-05-26 10:26:19',
//   bandwidth_rate: 90112,
//   bandwidth_burst: 68157440,
//   observed_bandwidth: 11219030,
//   advertised_bandwidth: 90112,
//   exit_policy: [ 'reject *:*' ],
//   exit_policy_summary: { reject: [Array] },
//   contact: 'email:usura[]sabotage.org url:https://386bsd.net proof:uri-rsa abuse:abuse[]sabotage.net twitter:adejoode ciissversion:2',
//   platform: 'Tor 0.4.7.13 on Linux',
//   version: '0.4.7.13',
//   version_status: 'recommended',
//   effective_family: [
//     '74C0C2705DB1192C03F19F7CD1BB234843B1A81F',
//     '7EA6EAD6FD83083C538F44038BBFA077587DD755'
//   ],
//   consensus_weight_fraction: 1.6330152e-7,
//   guard_probability: 0,
//   middle_probability: 4.898479e-7,
//   exit_probability: 0,
//   recommended_version: true,
//   measured: false,
//   unreachable_or_addresses: [ '[::]:443' ]
// },


// main()

// async function main () {
//   const relays = await requestDirectoryAuthorities()
//   await fs.promises.writeFile(__dirname + '/directory-authorities.json', JSON.stringify(relays, null, 2))
// }

export async function getRandomDirectoryAuthority () {
  const data = await fs.promises.readFile(__dirname + '/directory-authorities.json', 'utf8')
  const relays = JSON.parse(data)
  const selected = relays[Math.floor(Math.random()*relays.length)]
  return selected;
}

async function requestDirectoryAuthorities (opts = {}) {
  return requestOnionData({ flags: ['Authority'], ...opts })
}

async function requestOnionData ({ flags = [], ...opts } = {}) {
  const onionoo = new Onionoo();
  const query = {
    limit: 30,
    running: true,
    search: flags.map(flag => `flag:${flag}`).join(' '),
    order: '-consensus_weight',
    ...opts,
  };
  const response = await onionoo.details(query)
  const { relays } = response.body
  return relays
}

// perform fetch with retry and delay
const fetchWithRetry = async (url: string, opts: any = {}) => {
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
      if (retries > maxRetries) {
        throw err;
      }
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
};

// this is "dangerous" because we're performing it over http
export async function dangerouslyLookupOnionKey (peerIpPort: string, rsaIdDigest: Buffer) {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`
  const response = await fetchWithRetry(url)
  if (!response.ok) {
    throw new Error(`Failed to query peer for onion key: ${response.status} ${response.statusText}`)
  }
  const directoryRecord = await response.text()
  // console.log('fp lookup:', directoryRecord)
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord)
  // console.log('dangerouslyLookupOnionKey', ntorOnionKeyText)
  const ntorOnionKey = Buffer.from(ntorOnionKeyText, 'base64')
  return ntorOnionKey
}


export async function downloadMicrodescFromDirectory (directoryServerIpPort: string): string {
  const url = `http://${directoryServerIpPort}/tor/status-vote/current/consensus-microdesc`
  const response = await fetchWithRetry(url)
  if (!response.ok) {
    throw new Error(`Failed to query directory for microdesc: ${response.status} ${response.statusText}`)
  }
  const directoryRecord = await response.text()
  // console.log('microdesc lookup:', directoryRecord)
  return directoryRecord
}

function extractNtorOnionKey (directoryRecord: string): string {
  // ntor-onion-key RrV6Ae3gauyxgdTiIYvcRqJepNrAa4r2Fh8s0JI02wA
  const linePrefix = 'ntor-onion-key '
  const line = directoryRecord.split('\n').find(line => line.startsWith(linePrefix))
  if (!line) throw new Error('no ntor-onion-key line found')
  const ntorOnionKey = line.slice(linePrefix.length)
  return ntorOnionKey
}

export type MicroDescNodeInfo = {
  nickname?: string;
  rsaIdDigest?: Buffer;
  publication_date?: Date;
  ip_address?: string;
  onion_router_port?: number;
  directory_server_port?: number;
  // idk what this is
  mKey?: Buffer;
  flags?: string[];
  version?: string;
  protocols?: string;
  // bandwidth?: number;
  // unmeasured?: number;
  bandwidthStats?: Record<string, number>;
};

export function parseRelaysFromMicroDesc (microDescContent: string): MicroDescNodeInfo[] {
  const lines = microDescContent.split('\n');
  let relayInfo: MicroDescNodeInfo;
  const relayInfos: MicroDescNodeInfo[] = []

  // r test002a AB+0S6hvSEnm7ifzqh3QaYOxsm0 2038-01-01 00:00:00 127.0.0.1 5002 7002
  // m BY6mSHVSthDKuKGu8aiGKhuGkwZqJqDLs9RxY99gKYs
  // s Authority Exit Fast Guard HSDir Running Stable V2Dir Valid
  // v Tor 0.4.8.1-alpha-dev
  // pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
  // w Bandwidth=158 Unmeasured=1

  for (let line of lines) {
    const tokens = line.split(' ')
    if (tokens[0] === 'r') {
      let parts = line.split(' ');
      relayInfo = {
        nickname: parts[1],
        rsaIdDigest: Buffer.from(parts[2], 'base64'),
        publication_date: new Date(parts[3] + " " + parts[4]),
        ip_address: parts[5],
        onion_router_port: parseInt(parts[6]),
        directory_server_port: parseInt(parts[7]),
      };
      relayInfos.push(relayInfo)
    } else if (tokens[0] === 'm') {
      let parts = line.split(' ');
      relayInfo.mKey = Buffer.from(parts[1], 'base64');
    } else if (tokens[0] === 's') {
      let parts = line.split(' ');
      relayInfo.flags = parts.slice(1);
    } else if (tokens[0] === 'v') {
      let parts = line.split(' ');
      relayInfo.version = parts[1];
    } else if (tokens[0] === 'pr') {
      let parts = line.split(' ');
      relayInfo.protocols = parts[1];
    } else if (tokens[0] === 'w') {
      let parts = line.split(' ');
      relayInfo.bandwidthStats = {}
      // w Bandwidth=82000 Unmeasured=1
      parts.slice(1).forEach((token) => {
        let [type, value] = token.split('=');
        relayInfo.bandwidthStats[type] = parseInt(value);
      });
    }
  }

  return relayInfos;
}

// this is "dangerous" because we're performing it over http
export async function dangerouslyLookupPeerInfo (directoryServer: string, nodeInfo: MicroDescNodeInfo) {
  const onionKey = await dangerouslyLookupOnionKey(directoryServer, nodeInfo.rsaIdDigest)
  const peerInfo = microDescNodeInfoToPeerInfo(nodeInfo, onionKey)
  return peerInfo
}

export function microDescNodeInfoToPeerInfo (nodeInfo: MicroDescNodeInfo, onionKey: Buffer): PeerInfo {
  const linkSpecifiers: Array<LinkSpecifier> = []
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

  linkSpecifiers.push(addressAndPortToLinkSpecifier({
    type: AddressTypes.IPv4,
    ip: nodeInfo.ip_address,
    port: nodeInfo.onion_router_port,
  }))
  linkSpecifiers.push({
    type: LinkSpecifierTypes.LegacyId,
    data: nodeInfo.rsaIdDigest,
  })
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
  }
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
