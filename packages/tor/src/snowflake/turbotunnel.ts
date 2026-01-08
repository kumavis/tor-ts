import crypto from 'node:crypto';

// Snowflake "turbotunnel" mode constants (Token + ClientID prefix), compatible with:
// gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/turbotunnel

// Randomly generated magic prefix used to opt into turbotunnel mode.
export const TURBOTUNNEL_TOKEN = Uint8Array.from([0x12, 0x93, 0x60, 0x5d, 0x27, 0x81, 0x75, 0xf5]);

export type ClientId = Uint8Array; // 8 bytes

export function newClientId(): ClientId {
  return crypto.randomBytes(8);
}

export function buildTurbotunnelPreamble(clientId: ClientId): Uint8Array {
  if (clientId.byteLength !== 8) {
    throw new Error(`ClientID must be 8 bytes, got ${clientId.byteLength}`);
  }
  const out = new Uint8Array(TURBOTUNNEL_TOKEN.byteLength + clientId.byteLength);
  out.set(TURBOTUNNEL_TOKEN, 0);
  out.set(clientId, TURBOTUNNEL_TOKEN.byteLength);
  return out;
}
