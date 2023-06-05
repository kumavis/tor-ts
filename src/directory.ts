import fs from 'fs';
import Onionoo from 'onionoo';
import * as url from 'node:url';
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

export async function dangerouslyLookupOnionKey (peerIpPort: string, rsaIdDigest: Buffer) {
  const url = `http://${peerIpPort}/tor/server/fp/${rsaIdDigest.toString('hex').toUpperCase()}`
  const directoryRecord = await (await fetch(url)).text()
  const ntorOnionKeyText = extractNtorOnionKey(directoryRecord)
  console.log('dangerouslyLookupOnionKey', ntorOnionKeyText)
  const ntorOnionKey = Buffer.from(ntorOnionKeyText, 'base64')
  return ntorOnionKey
}

function extractNtorOnionKey (directoryRecord: string): string {
  // ntor-onion-key RrV6Ae3gauyxgdTiIYvcRqJepNrAa4r2Fh8s0JI02wA
  const linePrefix = 'ntor-onion-key '
  const line = directoryRecord.split('\n').find(line => line.startsWith(linePrefix))
  if (!line) throw new Error('no ntor-onion-key line found')
  const ntorOnionKey = line.slice(linePrefix.length)
  return ntorOnionKey
}