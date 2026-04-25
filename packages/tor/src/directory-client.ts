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

import { sha256 } from 'tor-crypto';
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

// Directory request retry constants
/** Maximum retry attempts for directory requests */
export const MAX_DIRECTORY_REQUEST_RETRIES = 16;
/** Base delay between retries in milliseconds */
const RETRY_BASE_DELAY_MS = 500;
/** Maximum delay between retries in milliseconds */
const RETRY_MAX_DELAY_MS = 10_000;

export class DirectoryClient {
  private circuit: Circuit;
  private timeoutMs: number;
  private maxRetries: number;

  constructor(circuit: Circuit, options?: { timeoutMs?: number; maxRetries?: number }) {
    this.circuit = circuit;
    this.timeoutMs = options?.timeoutMs ?? 30_000;
    this.maxRetries = options?.maxRetries ?? MAX_DIRECTORY_REQUEST_RETRIES;
  }

  /**
   * Make an HTTP request through the directory stream (single attempt).
   */
  private async requestOnce(
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

  /**
   * Make an HTTP request with retry logic.
   * Directory requests retry up to 16 times.
   */
  private async request(
    method: string,
    path: string,
    onProgress?: DownloadProgressCallback
  ): Promise<ParsedHttpResponse> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await this.requestOnce(method, path, onProgress);
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Don't retry on final attempt
        if (attempt < this.maxRetries - 1) {
          // Exponential backoff with jitter
          const delay = Math.min(
            RETRY_MAX_DELAY_MS,
            RETRY_BASE_DELAY_MS * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5)
          );
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    throw new Error(
      `Directory request failed after ${this.maxRetries} attempts: ${lastError?.message}`
    );
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
   * @param blindedPublicKeyBase64 - Standard base64-encoded blinded public key (no padding).
   *   Must use standard base64 (`+` and `/`), NOT base64url (`-` and `_`).
   *   Tor HSDirs reject base64url characters.
   */
  async downloadHsDescriptor(blindedPublicKeyBase64: string): Promise<string | null> {
    const path = `/tor/hs/3/${blindedPublicKeyBase64}`;
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

    // Join digests with '-' separator (standard base64, NOT base64url)
    // Per Tor spec: "-s are used instead of +s to separate items"
    // The '-' is the SEPARATOR between digests, not a replacement for '+' inside digests.
    // Standard base64 (with + and /) is used for the digest content itself.
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
 *
 * IMPORTANT: We compute the SHA256 hash of each microdescriptor and match it to the
 * expected digests. This ensures we never map wrong content to wrong digest, even if
 * some descriptors are missing from the response (which would shift indices).
 *
 * Per tor's microdesc_parse.c and arti's microdesc.rs:
 * - Digest is SHA256 of the raw microdescriptor text
 * - Text starts at "onion-key" and ends at the start of the next microdesc
 */
export function parseMicrodescriptorBatch(
  content: string,
  digestsBase64: string[]
): Map<string, ParsedMicrodescriptor> {
  const result = new Map<string, ParsedMicrodescriptor>();

  if (!content || content.trim() === '') {
    return result;
  }

  // Build a set of expected digests for quick lookup
  const expectedDigests = new Set(digestsBase64);

  // Find all microdescriptor boundaries in the raw content
  // Each microdescriptor starts with "onion-key" at the start of a line
  const boundaries: number[] = [];

  // Regex to find "onion-key" at the start of a line (or start of content)
  // Note: "onion-key" is always present per spec, even if the TAP key itself is omitted
  const startPattern = /(?:^|\n)(onion-key\r?\n)/g;
  let match;
  while ((match = startPattern.exec(content)) !== null) {
    // Position of "onion-key" (after the newline if present)
    boundaries.push(match.index === 0 ? 0 : match.index + 1);
  }

  // Sort boundaries
  boundaries.sort((a, b) => a - b);

  // Extract each microdescriptor text and compute its digest
  // Per tor's microdesc_extract_body: bodylen = start_of_next_microdesc - cp
  // The hash includes everything from "onion-key" to the start of the next microdesc
  for (let i = 0; i < boundaries.length; i++) {
    const start = boundaries[i]!;
    const end = i + 1 < boundaries.length ? boundaries[i + 1]! : content.length;

    // Extract the raw text - DO NOT trim, hash includes exact bytes
    const text = content.slice(start, end);

    if (!text) continue;

    // Compute SHA256 hash of the microdescriptor content (exact bytes)
    const hash = sha256(Buffer.from(text));
    const hashB64 = hash.toString('base64').replace(/=+$/, '');

    // Only include if this digest was requested
    if (expectedDigests.has(hashB64)) {
      const parsed = parseMicrodescriptor(text);
      result.set(hashB64, parsed);
    }
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
  // The full server descriptor always contains master-key-ed25519; extract
  // and pass it so the returned PeerInfo includes an Ed25519Id link
  // specifier. Without it, modern tor hidden services silently drop the
  // rendezvous extension built from INTRODUCE2.
  let ed25519IdentityKey: Buffer | undefined;
  try {
    ed25519IdentityKey = extractEd25519IdentityFromDescriptor(descriptor);
  } catch {
    // Older relays may omit the line; fall back to nodeInfo.ed25519Identity
    // inside microDescNodeInfoToPeerInfo.
  }
  return microDescNodeInfoToPeerInfo(nodeInfo, onionKey, ed25519IdentityKey);
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
  const peerInfo = microDescNodeInfoToPeerInfo(nodeInfo, onionKey, ed25519IdentityKey);
  return { peerInfo, ed25519IdentityKey };
}

import type { MicrodescManager, MicrodescProgressCallback } from './microdesc-manager.ts';

/**
 * Fetch exit policies for a list of relay nodes using the MicrodescManager.
 *
 * This mutates the input nodeInfos by setting their exitPolicy field.
 * Only fetches policies for nodes that have an mKey (microdescriptor digest).
 * Uses the MicrodescManager's cache to avoid redundant downloads.
 *
 * @param manager - MicrodescManager to use for downloads (handles caching)
 * @param nodeInfos - Array of relay nodes to fetch policies for
 * @param onProgress - Optional progress callback
 * @returns The number of policies successfully fetched
 */
export async function fetchExitPolicies(
  manager: MicrodescManager,
  nodeInfos: MicroDescNodeInfo[],
  onProgress?: MicrodescProgressCallback
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

  // Fetch microdescriptors via the manager (uses cache + deduplication)
  const microdescriptors = await manager.get(digestsBase64, onProgress);

  // Update node infos with exit policies and other data
  let fetchedCount = 0;
  for (const [digest, microdesc] of microdescriptors) {
    const node = digestToNode.get(digest);
    if (node) {
      if (microdesc.exitPolicy) {
        node.exitPolicy = microdesc.exitPolicy;
        fetchedCount++;
      }
    }
  }

  return fetchedCount;
}
