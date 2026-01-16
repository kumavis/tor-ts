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

export type DownloadProgress = {
  bytesReceived: number;
  estimatedTotalBytes: number | null;
  elapsedMs: number;
  speedBytesPerSec: number;
  estimatedRemainingMs: number | null;
};

export type DownloadProgressCallback = (progress: DownloadProgress) => void;

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
  private async request(
    method: string,
    path: string,
    onProgress?: DownloadProgressCallback
  ): Promise<ParsedHttpResponse> {
    const stream = await this.circuit.openDirectoryStream();

    const requestText = `${method} ${path} HTTP/1.0\r\n` + `Host: directory\r\n` + `\r\n`;

    const chunks: Buffer[] = [];
    const startTime = Date.now();
    let bytesReceived = 0;
    let estimatedTotalBytes: number | null = null;
    let lastProgressTime = startTime;

    stream.on('data', (d: Buffer) => {
      const chunk = Buffer.from(d);
      chunks.push(chunk);
      bytesReceived += chunk.length;

      // Try to extract Content-Length from first chunk if we don't have it
      if (estimatedTotalBytes === null && chunks.length <= 3) {
        const partialResponse = Buffer.concat(chunks).toString('utf8');
        const match = partialResponse.match(/Content-Length:\s*(\d+)/i);
        if (match) {
          // Add header size estimate (~200 bytes)
          estimatedTotalBytes = parseInt(match[1]!, 10) + 200;
        }
      }

      // Throttle progress updates to every 100ms
      const now = Date.now();
      if (onProgress && now - lastProgressTime >= 100) {
        lastProgressTime = now;
        const elapsedMs = now - startTime;
        const speedBytesPerSec = elapsedMs > 0 ? (bytesReceived / elapsedMs) * 1000 : 0;

        let estimatedRemainingMs: number | null = null;
        if (estimatedTotalBytes && speedBytesPerSec > 0) {
          const remainingBytes = estimatedTotalBytes - bytesReceived;
          estimatedRemainingMs = (remainingBytes / speedBytesPerSec) * 1000;
        }

        onProgress({
          bytesReceived,
          estimatedTotalBytes,
          elapsedMs,
          speedBytesPerSec,
          estimatedRemainingMs,
        });
      }
    });

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

    // Final progress update
    if (onProgress) {
      const elapsedMs = Date.now() - startTime;
      const speedBytesPerSec = elapsedMs > 0 ? (bytesReceived / elapsedMs) * 1000 : 0;
      onProgress({
        bytesReceived,
        estimatedTotalBytes: bytesReceived, // Now we know the exact size
        elapsedMs,
        speedBytesPerSec,
        estimatedRemainingMs: 0,
      });
    }

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
   *
   * @param onProgress - Optional callback for download progress updates
   */
  async downloadMicrodescConsensus(onProgress?: DownloadProgressCallback): Promise<string> {
    const response = await this.request(
      'GET',
      '/tor/status-vote/current/consensus-microdesc',
      onProgress
    );
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

  /**
   * Download authority key certificates.
   * Equivalent to: GET /tor/keys/all
   *
   * Returns all available key certificates from the directory cache.
   */
  async downloadKeyCertificates(): Promise<string> {
    const response = await this.request('GET', '/tor/keys/all');
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download key certificates: ${response.statusCode} ${response.statusText}`
      );
    }
    return response.body;
  }

  /**
   * Download a specific authority's key certificate by fingerprint.
   * Equivalent to: GET /tor/keys/fp/{fingerprint}
   *
   * @param fingerprint - The authority's identity fingerprint (hex, uppercase)
   */
  async downloadKeyCertificate(fingerprint: string): Promise<string | null> {
    const response = await this.request('GET', `/tor/keys/fp/${fingerprint.toUpperCase()}`);
    if (response.statusCode === 404) {
      return null;
    }
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download key certificate for ${fingerprint}: ${response.statusCode} ${response.statusText}`
      );
    }
    return response.body;
  }

  /**
   * Download microdescriptors by their base64-encoded digests.
   * Equivalent to: GET /tor/micro/d/{hash1}-{hash2}-...
   *
   * Microdescriptors contain the exit policy summary (p line) and other info.
   * The hashes are the base64-encoded SHA256 digests from the consensus 'm' lines.
   *
   * @param digestsBase64 - Array of base64-encoded microdescriptor digests (without padding)
   * @returns Raw microdescriptor content (may contain multiple descriptors)
   */
  async downloadMicrodescriptors(digestsBase64: string[]): Promise<string> {
    if (digestsBase64.length === 0) {
      return '';
    }

    // Convert base64 digests to the format expected by the directory server
    // The digests need to be joined with hyphens
    const digestList = digestsBase64.join('-');
    const path = `/tor/micro/d/${digestList}`;

    const response = await this.request('GET', path);
    if (response.statusCode === 404) {
      return ''; // No microdescriptors found
    }
    if (response.statusCode !== 200) {
      throw new Error(
        `Failed to download microdescriptors: ${response.statusCode} ${response.statusText}`
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

import { parseExitPolicySummary, type ExitPolicy } from './exit-policy.ts';

/**
 * Parsed microdescriptor containing exit policy and other info.
 */
export type ParsedMicrodescriptor = {
  /** The onion-key line (RSA public key, PEM format) - optional in newer microdescriptors */
  onionKey?: string;
  /** The ntor-onion-key (curve25519 public key, base64) */
  ntorOnionKey?: Buffer;
  /** Exit policy summary */
  exitPolicy?: ExitPolicy;
  /** IPv6 exit policy summary */
  exitPolicyV6?: ExitPolicy;
  /** Ed25519 identity key */
  ed25519Identity?: Buffer;
  /** Family IDs */
  familyIds?: string[];
};

/**
 * Parse a single microdescriptor.
 *
 * Microdescriptor format:
 * ```
 * onion-key
 * -----BEGIN RSA PUBLIC KEY-----
 * ...
 * -----END RSA PUBLIC KEY-----
 * ntor-onion-key <base64>
 * p accept 80,443
 * p6 accept 80,443
 * id ed25519 <base64>
 * ```
 */
export function parseMicrodescriptor(content: string): ParsedMicrodescriptor {
  const result: ParsedMicrodescriptor = {};
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (line.startsWith('ntor-onion-key ')) {
      const keyB64 = line.slice('ntor-onion-key '.length).trim();
      result.ntorOnionKey = Buffer.from(keyB64, 'base64');
    } else if (line.startsWith('p ')) {
      const policy = parseExitPolicySummary(line);
      if (policy) result.exitPolicy = policy;
    } else if (line.startsWith('p6 ')) {
      // IPv6 policy - similar format but prefixed with p6
      const policyLine = 'p ' + line.slice(3); // Convert to standard format for parsing
      const policy = parseExitPolicySummary(policyLine);
      if (policy) result.exitPolicyV6 = policy;
    } else if (line.startsWith('id ed25519 ')) {
      const keyB64 = line.slice('id ed25519 '.length).trim();
      result.ed25519Identity = Buffer.from(keyB64, 'base64');
    } else if (line.startsWith('family ')) {
      result.familyIds = line.slice('family '.length).trim().split(' ');
    }
  }

  return result;
}

/**
 * Parse multiple microdescriptors from a batch response.
 *
 * Microdescriptors are separated by "onion-key" lines (or "ntor-onion-key" if no RSA key).
 * Returns a map from microdescriptor digest to parsed descriptor.
 */
export function parseMicrodescriptorBatch(
  content: string,
  digestsBase64: string[]
): Map<string, ParsedMicrodescriptor> {
  const result = new Map<string, ParsedMicrodescriptor>();

  if (!content || content.trim() === '') {
    return result;
  }

  // Split on @last annotation or on "onion-key" / "ntor-onion-key" at start of line
  // Microdescriptors are separated by the start of a new one
  const descriptorTexts: string[] = [];
  let currentDescriptor: string[] = [];

  for (const line of content.split('\n')) {
    // A new microdescriptor starts with "onion-key" or "ntor-onion-key"
    if (
      (line === 'onion-key' || line.startsWith('ntor-onion-key ')) &&
      currentDescriptor.length > 0
    ) {
      descriptorTexts.push(currentDescriptor.join('\n'));
      currentDescriptor = [];
    }
    currentDescriptor.push(line);
  }

  // Don't forget the last descriptor
  if (currentDescriptor.length > 0) {
    descriptorTexts.push(currentDescriptor.join('\n'));
  }

  // Parse each descriptor and match to digests
  // Note: The order of descriptors in the response matches the order of digests requested
  for (let i = 0; i < descriptorTexts.length && i < digestsBase64.length; i++) {
    const text = descriptorTexts[i]!;
    const digest = digestsBase64[i]!;
    const parsed = parseMicrodescriptor(text);
    result.set(digest, parsed);
  }

  return result;
}

import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './build-circuit/directory.ts';
import {
  parseMicroDescConsensus,
  parseAndVerifyConsensus,
  microDescNodeInfoToPeerInfo,
  dangerouslyTrustUnverifiedConsensus,
} from './build-circuit/directory.ts';

import type { AuthorityKeyCertificate } from './consensus-signature.ts';
import { parseAllKeyCertificates } from './consensus-signature.ts';

/**
 * Options for fetching and verifying consensus.
 */
export type FetchConsensusOptions = {
  /**
   * Timeout for directory operations in milliseconds.
   * Default: 30000 (30 seconds)
   */
  timeoutMs?: number;

  /**
   * **DANGEROUS**: Skip consensus signature verification entirely.
   *
   * WARNING: This disables a critical security check. The consensus document
   * could be forged by an attacker to direct you to malicious relays.
   *
   * Only use this option if:
   * - You're in a test environment
   * - You're debugging/developing and understand the risks
   * - The crypto implementation for your platform is not yet complete
   *
   * Default: false
   */
  dangerouslySkipSignatureVerification?: boolean;

  /**
   * Callback for consensus download progress.
   */
  onProgress?: DownloadProgressCallback;

  /**
   * Callback for status updates.
   */
  onStatus?: (status: string) => void;
};

/**
 * Result of fetching and verifying consensus.
 */
export type FetchConsensusResult = {
  /** The parsed and verified consensus */
  consensus: VerifiedMicroDescConsensus;
  /** The raw consensus content (useful for caching) */
  rawContent: string;
  /** The key certificates used for verification */
  keyCertificates: AuthorityKeyCertificate[];
  /** The DirectoryClient used (can be reused for further lookups) */
  dirClient: DirectoryClient;
};

/**
 * Fetch and verify consensus from a directory server via a Tor circuit.
 *
 * This is the standard flow for obtaining a verified consensus:
 * 1. Download key certificates from directory authorities
 * 2. Download the microdescriptor consensus
 * 3. Parse and verify consensus signatures
 *
 * @param circuit - The circuit to use for directory requests
 * @param options - Options for fetching and verification
 * @returns The verified consensus and related data
 */
export async function fetchAndVerifyConsensus(
  circuit: Circuit,
  options: FetchConsensusOptions = {}
): Promise<FetchConsensusResult> {
  const { timeoutMs, dangerouslySkipSignatureVerification = false, onProgress, onStatus } = options;

  const dirClient = new DirectoryClient(circuit, timeoutMs ? { timeoutMs } : undefined);

  // Download consensus
  onStatus?.('Downloading network consensus...');
  const rawContent = await dirClient.downloadMicrodescConsensus(onProgress);

  let consensus: VerifiedMicroDescConsensus;
  let keyCertificates: AuthorityKeyCertificate[] = [];

  if (dangerouslySkipSignatureVerification) {
    // Parse without verification - only for testing (e.g., Chutney)
    const unverified = parseMicroDescConsensus(rawContent);
    // SKIP VERIFICATION: Caller explicitly requested dangerouslySkipSignatureVerification.
    // This should only be used in test environments (Chutney) where directory
    // authorities don't match mainnet authorities.
    consensus = dangerouslyTrustUnverifiedConsensus(
      unverified,
      'dangerouslySkipSignatureVerification=true (caller explicitly skipped)'
    );
  } else {
    // Download key certificates for signature verification
    onStatus?.('Downloading authority key certificates...');
    const keyCertsText = await dirClient.downloadKeyCertificates();
    keyCertificates = parseAllKeyCertificates(keyCertsText);
    onStatus?.(`Downloaded ${keyCertificates.length} key certificates`);

    // Parse and verify
    const result = await parseAndVerifyConsensus(rawContent, {
      keyCertificates,
    });
    consensus = result.consensus;
  }

  if (consensus.relays.length === 0) {
    throw new Error('No relays found in consensus');
  }

  return {
    consensus,
    rawContent,
    keyCertificates,
    dirClient,
  };
}

// Re-export consensus signature types
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

/**
 * Fetch exit policies for a list of relay nodes by downloading their microdescriptors.
 *
 * This mutates the input nodeInfos by setting their exitPolicy field.
 * Only fetches policies for nodes that have an mKey (microdescriptor digest).
 *
 * @param client - DirectoryClient to use for downloads
 * @param nodeInfos - Array of relay nodes to fetch policies for
 * @returns The number of policies successfully fetched
 */
export async function fetchExitPolicies(
  client: DirectoryClient,
  nodeInfos: MicroDescNodeInfo[]
): Promise<number> {
  // Filter to nodes with mKey and build digest list
  const nodesWithMKey = nodeInfos.filter((n) => n.mKey);
  if (nodesWithMKey.length === 0) {
    return 0;
  }

  // Convert mKey buffers to base64 (without padding, as used in directory requests)
  const digestsBase64 = nodesWithMKey.map((n) => n.mKey!.toString('base64').replace(/=+$/, ''));

  // Build a map from digest to node for quick lookup
  const digestToNode = new Map<string, MicroDescNodeInfo>();
  for (let i = 0; i < nodesWithMKey.length; i++) {
    digestToNode.set(digestsBase64[i]!, nodesWithMKey[i]!);
  }

  // Download microdescriptors in batches (directory servers may limit request size)
  const BATCH_SIZE = 92; // ~92 base64 digests fit in reasonable URL length
  let fetchedCount = 0;

  for (let i = 0; i < digestsBase64.length; i += BATCH_SIZE) {
    const batchDigests = digestsBase64.slice(i, i + BATCH_SIZE);
    try {
      const content = await client.downloadMicrodescriptors(batchDigests);
      const parsed = parseMicrodescriptorBatch(content, batchDigests);

      // Update node infos with exit policies
      for (const [digest, microdesc] of parsed) {
        const node = digestToNode.get(digest);
        if (node && microdesc.exitPolicy) {
          node.exitPolicy = microdesc.exitPolicy;
          fetchedCount++;
        }
      }
    } catch {
      // Continue with other batches if one fails
      continue;
    }
  }

  return fetchedCount;
}
