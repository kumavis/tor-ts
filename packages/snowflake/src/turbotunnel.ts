import crypto from 'node:crypto';
import { encodeEncapsulatedPadding } from './encapsulation.ts';

// Snowflake "turbotunnel" mode constants (Token + ClientID prefix), compatible with:
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/turbotunnel

/** Randomly generated magic prefix used to opt into turbotunnel mode. */
export const TURBOTUNNEL_TOKEN = Uint8Array.from([0x12, 0x93, 0x60, 0x5d, 0x27, 0x81, 0x75, 0xf5]);

export type ClientId = Uint8Array; // 8 bytes

/** Canonical client emits 1900-2099 bytes of encapsulated padding after Token+ClientID. */
export const DEFAULT_PADDING_MIN = 1900;
export const DEFAULT_PADDING_MAX = 2099;

export type BuildTurbotunnelPreambleOptions = {
  /** Include canonical random padding (defaults to true). */
  padding?: boolean;
  /** Fixed padding size (bypasses paddingMin/Max). Useful for tests. */
  paddingSize?: number;
  paddingMin?: number;
  paddingMax?: number;
  randomBytes?: (n: number) => Uint8Array;
};

export function newClientId(): ClientId {
  return crypto.randomBytes(8);
}

/**
 * Build the turbotunnel preamble sent on a fresh carrier connection.
 *
 * Layout: `Token (8B) || ClientID (8B) || [encapsulated padding 1900..2099 B]`
 *
 * The padding obscures the otherwise fixed 16-byte session-open signature
 * that would fingerprint every Snowflake client at the network level.
 * Matches tpo/snowflake:client/lib/snowflake.go:344-365.
 */
export function buildTurbotunnelPreamble(
  clientId: ClientId,
  opts: BuildTurbotunnelPreambleOptions = {}
): Uint8Array {
  if (clientId.byteLength !== 8) {
    throw new Error(`ClientID must be 8 bytes, got ${clientId.byteLength}`);
  }

  const withPadding = opts.padding ?? true;

  const header = new Uint8Array(TURBOTUNNEL_TOKEN.byteLength + clientId.byteLength);
  header.set(TURBOTUNNEL_TOKEN, 0);
  header.set(clientId, TURBOTUNNEL_TOKEN.byteLength);

  if (!withPadding) return header;

  const min = opts.paddingMin ?? DEFAULT_PADDING_MIN;
  const max = opts.paddingMax ?? DEFAULT_PADDING_MAX;
  if (max < min) throw new Error('paddingMax < paddingMin');

  const randomBytes = opts.randomBytes ?? ((n: number) => Uint8Array.from(crypto.randomBytes(n)));

  const size = opts.paddingSize ?? min + Math.floor((randomBytes(1)[0]! / 256) * (max - min + 1));

  const pad = encodeEncapsulatedPadding(size, randomBytes);

  const out = new Uint8Array(header.byteLength + pad.byteLength);
  out.set(header, 0);
  out.set(pad, header.byteLength);
  return out;
}
