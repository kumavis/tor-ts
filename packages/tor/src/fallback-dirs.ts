/**
 * Hardcoded Fallback Directory Mirrors for Safe Bootstrap.
 *
 * Per Tor spec (dir-spec.txt § 6.2), clients should ship with hardcoded
 * fallback directories to enable safe bootstrap without plain HTTP requests.
 *
 * Each entry contains (matching Tor's fallback_dirs.inc format):
 * - ip: IPv4 address
 * - orPort: Onion Router port (for TLS connection)
 * - rsaIdDigest: 20-byte SHA1 of RSA identity key
 *
 * These are used to:
 * 1. Connect via TLS to the OR port
 * 2. Verify the relay's RSA identity during TLS handshake
 * 3. Use CREATE_FAST for first-hop circuit (no onion key needed)
 * 4. Use RELAY_BEGIN_DIR to fetch directory info over encrypted channel
 *
 * Note: CREATE_FAST is used because:
 * - The ntor onion key is not included in fallback_dirs.inc (it rotates)
 * - CREATE_FAST provides encryption using random data exchange
 * - The connection is already protected by TLS to a verified relay
 *
 * This list is from Tor's official fallback_dirs.inc:
 * https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/fallback_dirs.inc
 *
 * The list should be updated periodically to match upstream.
 */

import { LinkSpecifierTypes, AddressTypes, addressAndPortToLinkSpecifier } from './messaging.ts';
import type { PeerInfo } from './circuit.ts';

export type FallbackDirectory = {
  ip: string;
  orPort: number;
  rsaIdDigest: Buffer; // 20 bytes - SHA1 of RSA identity
  ipv6?: string; // Optional IPv6 address
  ipv6Port?: number;
};

/**
 * Parse a fallback directory entry from the Tor fallback_dirs.inc format.
 *
 * Format in fallback_dirs.inc:
 *   "IP orport=PORT id=RSAHEX"
 *   " ipv6=[IPV6]:PORT"  (optional)
 */
export function parseFallbackEntry(
  ip: string,
  orPort: number,
  rsaIdHex: string,
  ipv6?: string,
  ipv6Port?: number
): FallbackDirectory {
  const rsaIdDigest = Buffer.from(rsaIdHex, 'hex');
  if (rsaIdDigest.length !== 20) {
    throw new Error(`Invalid RSA ID digest length: ${rsaIdDigest.length}, expected 20`);
  }
  const result: FallbackDirectory = { ip, orPort, rsaIdDigest };
  if (ipv6 !== undefined) result.ipv6 = ipv6;
  if (ipv6Port !== undefined) result.ipv6Port = ipv6Port;
  return result;
}

/**
 * Hardcoded fallback directories from Tor's fallback_dirs.inc.
 *
 * Source: https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/fallback_dirs.inc
 * Last updated: 2024-01 (should be refreshed periodically)
 */
export const FALLBACK_DIRECTORIES: FallbackDirectory[] = [
  // Sample entries from fallback_dirs.inc (production should include all ~150)
  parseFallbackEntry('216.9.227.166', 445, 'EF8DF732D0F307F63011B81CA44257E30BEF2B5C'),
  parseFallbackEntry('45.155.249.124', 38017, '4BCB5FC1BE126EF5302447472930A9034070FB08'),
  parseFallbackEntry('124.198.131.138', 80, '47B56BBC6573EA37A886736145EBB5D6F3EC7480'),
  parseFallbackEntry('185.235.146.29', 443, '5A6976353F19DAB6EB63A2CB95C00039B7D4064A'),
  parseFallbackEntry('81.7.18.7', 9001, '0C475BA4D3AA3C289B716F95954CAD616E50C4E5'),
  parseFallbackEntry('188.214.88.33', 9001, 'BC5D9898817E3F07CDD4292B35DA6819368710B7'),
  parseFallbackEntry('96.9.98.210', 443, '9D98766220B32CBD882C1B799D20BE71C3BEAAF6'),
  parseFallbackEntry('45.95.169.109', 7430, '7C9FC7C99D7F83980E621BA8D4E0D40FCE53104F'),
  parseFallbackEntry('192.42.116.214', 9000, '31BA70D5332FE49C500FBFFDB0CC5B9D3803CFBF'),
  parseFallbackEntry('91.208.75.153', 443, '5952434A60B6881FFFAF5C3B1C08682FAF5885F5'),
  parseFallbackEntry('64.65.1.112', 443, '56912E60E4E3003A277B9E46C7EFBC5E01C14C18'),
  parseFallbackEntry('185.40.4.101', 13443, '45FA08CC2A41FE183E4FF5DEDB3AAB13C01FAD39'),
  parseFallbackEntry('64.65.0.7', 443, '862F828CC223FF9916ADFCCEC47BC5E9839413BA'),
  parseFallbackEntry('64.65.62.202', 443, '032E78EDF6708A3C70ABCC2AED9FAABDB7DB4C43'),
];

/**
 * Select a random fallback directory.
 */
export function getRandomFallbackDirectory(): FallbackDirectory {
  const index = Math.floor(Math.random() * FALLBACK_DIRECTORIES.length);
  const fallback = FALLBACK_DIRECTORIES[index];
  if (!fallback) {
    throw new Error('No fallback directories available');
  }
  return fallback;
}

/**
 * Convert a FallbackDirectory to PeerInfo for circuit building.
 *
 * Note: onionKey is empty because we use CREATE_FAST for fallback connections.
 * CREATE_FAST doesn't require the ntor onion key - it uses random data exchange.
 */
export function fallbackToPeerInfo(fallback: FallbackDirectory): PeerInfo {
  return {
    // Empty onionKey triggers CREATE_FAST instead of CREATE2/ntor
    onionKey: Buffer.alloc(0),
    rsaIdDigest: fallback.rsaIdDigest,
    linkSpecifiers: [
      addressAndPortToLinkSpecifier({
        type: AddressTypes.IPv4,
        ip: fallback.ip,
        port: fallback.orPort,
      }),
      {
        type: LinkSpecifierTypes.LegacyId,
        data: fallback.rsaIdDigest,
      },
    ],
  };
}
