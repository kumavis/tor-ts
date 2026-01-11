/**
 * DirectoryClient provides safe directory lookups over Tor circuits.
 *
 * Instead of making direct HTTP requests (which leak the client's IP),
 * this class uses RELAY_BEGIN_DIR to tunnel directory requests through
 * an encrypted Tor circuit.
 *
 * Usage:
 *   const circuit = ... // build a circuit to a relay that serves directory info
 *   const client = new DirectoryClient(circuit);
 *   const consensus = await client.downloadMicrodescConsensus();
 *   const descriptor = await client.downloadRelayServerDescriptor(rsaIdDigest);
 */

import type { Circuit, PeerInfo } from './circuit.ts';
import { parseHttpResponse, type ParsedHttpResponse } from './http-parse.ts';

// Re-export the response type for external use
export type { ParsedHttpResponse as DirectoryResponse } from './http-parse.ts';

export class DirectoryClient {
  private circuit: Circuit;
  private timeoutMs: number;

  constructor(circuit: Circuit, options?: { timeoutMs?: number }) {
    this.circuit = circuit;
    this.timeoutMs = options?.timeoutMs ?? 30_000;
  }

  /**
   * Make an HTTP request through the directory stream.
   */
  private async request(method: string, path: string): Promise<ParsedHttpResponse> {
    const stream = await this.circuit.openDirectoryStream();

    const requestText = `${method} ${path} HTTP/1.0\r\n` + `Host: directory\r\n` + `\r\n`;

    const chunks: Buffer[] = [];
    stream.on('data', (d: Buffer) => chunks.push(Buffer.from(d)));

    const endedP = new Promise<void>((resolve, reject) => {
      stream.once('end', (err?: Error) => {
        if (err) reject(err);
        else resolve();
      });
    });

    await Promise.race([
      stream.write(Buffer.from(requestText, 'ascii')),
      this.timeoutRejection('directory request write timeout'),
    ]);

    await Promise.race([endedP, this.timeoutRejection('directory request read timeout')]);

    const raw = Buffer.concat(chunks).toString('utf8');
    return parseHttpResponse(raw);
  }

  private timeoutRejection(message: string): Promise<never> {
    return new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error(message)), this.timeoutMs);
    });
  }

  /**
   * Download the consensus-microdesc document from the directory.
   * Equivalent to: GET /tor/status-vote/current/consensus-microdesc
   */
  async downloadMicrodescConsensus(): Promise<string> {
    const response = await this.request('GET', '/tor/status-vote/current/consensus-microdesc');
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download consensus-microdesc: ${response.statusCode} ${response.statusText}`
      );
    }
    return response.body;
  }

  /**
   * Download a relay's server descriptor by RSA identity fingerprint.
   * Equivalent to: GET /tor/server/fp/{fingerprint}
   */
  async downloadRelayServerDescriptor(rsaIdDigest: Buffer): Promise<string> {
    const fingerprint = rsaIdDigest.toString('hex').toUpperCase();
    const response = await this.request('GET', `/tor/server/fp/${fingerprint}`);
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download relay descriptor for ${fingerprint}: ${response.statusCode} ${response.statusText}`
      );
    }
    return response.body;
  }

  /**
   * Download a hidden service descriptor by blinded public key.
   * Equivalent to: GET /tor/hs/3/{blinded-key}
   *
   * @param blindedPublicKeyBase64Url - Base64url-encoded blinded public key (no padding)
   */
  async downloadHsDescriptor(blindedPublicKeyBase64Url: string): Promise<string | null> {
    const path = `/tor/hs/3/${encodeURIComponent(blindedPublicKeyBase64Url)}`;
    const response = await this.request('GET', path);
    if (response.statusCode === 404) {
      return null;
    }
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download HS descriptor: ${response.statusCode} ${response.statusText}`
      );
    }
    return response.body;
  }
}

/**
 * Helper to extract ntor-onion-key from a relay server descriptor.
 */
export function extractNtorOnionKeyFromDescriptor(descriptorText: string): Buffer {
  const linePrefix = 'ntor-onion-key ';
  const line = descriptorText.split('\n').find((l) => l.startsWith(linePrefix));
  if (!line) {
    throw new Error('no ntor-onion-key line found in descriptor');
  }
  const ntorOnionKeyB64 = line.slice(linePrefix.length).trim();
  return Buffer.from(ntorOnionKeyB64, 'base64');
}

/**
 * Helper to extract master-key-ed25519 from a relay server descriptor.
 */
export function extractEd25519IdentityFromDescriptor(descriptorText: string): Buffer {
  const linePrefix = 'master-key-ed25519 ';
  const line = descriptorText.split('\n').find((l) => l.startsWith(linePrefix));
  if (!line) {
    throw new Error('no master-key-ed25519 line found in descriptor');
  }
  const keyB64 = line.slice(linePrefix.length).trim();
  const key = Buffer.from(keyB64, 'base64');
  if (key.length !== 32) {
    throw new Error(`Expected 32-byte ed25519 identity, got ${key.length}`);
  }
  return key;
}

// Re-export types from directory.ts for convenience
import type {
  MicroDescNodeInfo,
  MicroDescConsensus,
  ParseMicroDescConsensusOptions,
} from './build-circuit/directory.ts';
import { parseMicroDescConsensus, microDescNodeInfoToPeerInfo } from './build-circuit/directory.ts';

export {
  parseMicroDescConsensus,
  type MicroDescNodeInfo,
  type MicroDescConsensus,
  type ParseMicroDescConsensusOptions,
};

// Re-export consensus signature types
export type {
  ConsensusSignature,
  ConsensusVerificationResult,
  DirectoryAuthorityIdentity,
  AuthorityKeyCertificate,
  VerifyConsensusOptions,
  SignatureVerificationResult,
} from './consensus-signature.ts';

export {
  DIRECTORY_AUTHORITIES,
  verifyConsensusSignatures,
  parseConsensusSignatures,
  parseKeyCertificate,
  findAuthorityByFingerprint,
  extractAuthorityFingerprints,
} from './consensus-signature.ts';

/**
 * Safely look up a relay's onion key by downloading its server descriptor
 * through a circuit directory stream.
 *
 * This is the safe equivalent of `dangerouslyLookupOnionKey`.
 */
export async function lookupOnionKey(
  client: DirectoryClient,
  rsaIdDigest: Buffer
): Promise<Buffer> {
  const descriptor = await client.downloadRelayServerDescriptor(rsaIdDigest);
  return extractNtorOnionKeyFromDescriptor(descriptor);
}

/**
 * Safely look up PeerInfo for a relay by downloading its server descriptor
 * through a circuit directory stream.
 *
 * This is the safe equivalent of `dangerouslyLookupPeerInfo`.
 */
export async function lookupPeerInfo(
  client: DirectoryClient,
  nodeInfo: MicroDescNodeInfo
): Promise<PeerInfo> {
  const descriptor = await client.downloadRelayServerDescriptor(nodeInfo.rsaIdDigest);
  const onionKey = extractNtorOnionKeyFromDescriptor(descriptor);
  return microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
}

/**
 * Safely look up PeerInfo with Ed25519 identity for a relay by downloading
 * its server descriptor through a circuit directory stream.
 *
 * This is the safe equivalent of `dangerouslyLookupPeerInfoWithEd25519IdentityKey`.
 */
export async function lookupPeerInfoWithEd25519IdentityKey(
  client: DirectoryClient,
  nodeInfo: MicroDescNodeInfo
): Promise<{ peerInfo: PeerInfo; ed25519IdentityKey: Buffer }> {
  const descriptor = await client.downloadRelayServerDescriptor(nodeInfo.rsaIdDigest);
  const onionKey = extractNtorOnionKeyFromDescriptor(descriptor);
  const ed25519IdentityKey = extractEd25519IdentityFromDescriptor(descriptor);
  const peerInfo = microDescNodeInfoToPeerInfo(nodeInfo, onionKey);
  return { peerInfo, ed25519IdentityKey };
}
