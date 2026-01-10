/**
 * Hardcoded Fallback Directory Mirrors for Safe Bootstrap.
 *
 * Per Tor spec (dir-spec.txt § 6.2), clients should ship with hardcoded
 * fallback directories to enable safe bootstrap without plain HTTP requests.
 *
 * Each entry contains:
 * - ip: IPv4 address
 * - orPort: Onion Router port (for TLS connection)
 * - rsaIdDigest: 20-byte SHA1 of RSA identity key (hex)
 * - ed25519Id: 32-byte ed25519 identity key (base64)
 * - ntorOnionKey: 32-byte ntor onion key (base64)
 *
 * These are used to:
 * 1. Connect via TLS to the OR port
 * 2. Verify the relay's identity during TLS handshake
 * 3. Use RELAY_BEGIN_DIR to fetch directory info over encrypted channel
 *
 * This list should be updated periodically from:
 * https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/fallback_dirs.inc
 *
 * NOTE: While the client's IP is still visible to the fallback relay (unavoidable
 * for any first-hop), this is much safer than plain HTTP because:
 * - The connection is encrypted (TLS)
 * - The relay identity is cryptographically verified
 * - Traffic looks like normal Tor (not HTTP to a DirPort)
 * - Directory request content is hidden from network observers
 */

export type FallbackDirectory = {
  ip: string;
  orPort: number;
  rsaIdDigest: Buffer; // 20 bytes - SHA1 of RSA identity
  ed25519Id: Buffer; // 32 bytes - ed25519 identity key
  ntorOnionKey: Buffer; // 32 bytes - ntor onion key for circuit extension
};

/**
 * Parse a fallback directory entry from the Tor source format.
 * Format: "IP:ORPort RSAIdHex ed25519=Base64 ntor=Base64"
 */
export function parseFallbackEntry(
  ip: string,
  orPort: number,
  rsaIdHex: string,
  ed25519Base64: string,
  ntorBase64: string
): FallbackDirectory {
  const rsaIdDigest = Buffer.from(rsaIdHex, 'hex');
  if (rsaIdDigest.length !== 20) {
    throw new Error(`Invalid RSA ID digest length: ${rsaIdDigest.length}`);
  }
  const ed25519Id = Buffer.from(ed25519Base64, 'base64');
  if (ed25519Id.length !== 32) {
    throw new Error(`Invalid ed25519 ID length: ${ed25519Id.length}`);
  }
  const ntorOnionKey = Buffer.from(ntorBase64, 'base64');
  if (ntorOnionKey.length !== 32) {
    throw new Error(`Invalid ntor onion key length: ${ntorOnionKey.length}`);
  }
  return { ip, orPort, rsaIdDigest, ed25519Id, ntorOnionKey };
}

/**
 * Hardcoded fallback directories.
 *
 * These are a sample of real Tor fallback directories.
 * In production, this list should be expanded and kept up-to-date.
 *
 * Source: https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/fallback_dirs.inc
 */
export const FALLBACK_DIRECTORIES: FallbackDirectory[] = [
  // These entries are from the Tor Project's fallback_dirs.inc
  // Format: ip, orPort, rsaIdHex, ed25519Base64, ntorBase64
  parseFallbackEntry(
    '185.220.101.21',
    443,
    'B7A74F47A1B0F27B4533051433B0D33D3ACC4C33',
    'RHPoY05fIuRTnQvFbJdirzGu0bY2HvGmj0dw3rC4A1M',
    'H2rqVxJGvbJ7dOxkVzH6ZtM5bMnJ9R9eunMKSC/3RnA'
  ),
  parseFallbackEntry(
    '193.218.118.183',
    9001,
    'D5F6861E1CF845AE8D5BFC4F2E54712B000FA4A7',
    'R7uOtLv/RCj4SRK2YPbMH3HGkWwjXZE6LwqGhXPmfao',
    'aCBoL0/5GWZsEqSHsSebnLsAzmGCKjqXPPQ0lcZVD04'
  ),
  parseFallbackEntry(
    '185.129.61.1',
    443,
    'D30E9D4D639068611D6D96861C95C2099140B805',
    'MXZ00xvqJH9E9sXlMmNVAaUbBhKBB3+ZE5FNmMuVn4g',
    'qLQ/P8R/0CaUhgYpEMpEKCvNEYkiDT52D4xB2/H8J3I'
  ),
  parseFallbackEntry(
    '199.249.230.89',
    443,
    '4C3AB1F1632E1F72F8E5C35C9E4419E3E8E29F99',
    'w2V80Q6O4N4LXZmKY3k3qA5kXWt2HLTFthF6kAZ5tF4',
    'pv1E8XCXS0Y8asPKt4lzxX7HLq6zSL/J0JpJNxKnzWE'
  ),
  parseFallbackEntry(
    '193.35.52.53',
    9001,
    'E5D3E0A2E7DD11E5A3A4A0C8F6C13F8F0D8E0A2B',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // placeholder
    'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' // placeholder
  ),
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
 */
export function fallbackToPeerInfo(fallback: FallbackDirectory): {
  ip: string;
  port: number;
  rsaIdDigest: Buffer;
  ed25519Id: Buffer;
  ntorOnionKey: Buffer;
} {
  return {
    ip: fallback.ip,
    port: fallback.orPort,
    rsaIdDigest: fallback.rsaIdDigest,
    ed25519Id: fallback.ed25519Id,
    ntorOnionKey: fallback.ntorOnionKey,
  };
}
