/**
 * Snowflake broker client for WebRTC signaling.
 *
 * The broker matches Snowflake clients with volunteer proxies.
 * Protocol compatible with:
 * gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib
 *
 * Flow:
 * 1. Client creates an SDP offer
 * 2. Client sends offer to broker via POST /client
 * 3. Broker matches with available proxy and returns proxy's SDP answer
 * 4. Client uses answer to complete WebRTC connection
 */

export type BrokerClientOptions = {
  /**
   * URL of the Snowflake broker.
   * Defaults to the Tor Project's production broker.
   */
  brokerUrl?: string;

  /**
   * Front domain for domain fronting (e.g., 'www.fastly.com').
   * When set, requests go through the front domain for censorship resistance.
   */
  frontDomain?: string;

  /**
   * NAT type reported to broker.
   * 'unknown' is the default and works for most cases.
   */
  natType?: 'unknown' | 'unrestricted' | 'restricted';

  /**
   * Number of relay addresses to request from broker.
   * Defaults to 1.
   */
  numRelayAddresses?: number;
};

export type BrokerAnswer = {
  /** The SDP answer from the proxy */
  answer: string;
  /** Error message if any */
  error?: string;
};

const DEFAULT_BROKER_URL = 'https://snowflake-broker.torproject.net/';

/**
 * Client for the Snowflake broker rendezvous service.
 * Handles signaling between Snowflake clients and volunteer proxies.
 */
export class SnowflakeBrokerClient {
  readonly brokerUrl: string;
  readonly frontDomain: string | undefined;
  readonly natType: string;
  readonly numRelayAddresses: number;

  constructor(opts: BrokerClientOptions = {}) {
    this.brokerUrl = opts.brokerUrl ?? DEFAULT_BROKER_URL;
    this.frontDomain = opts.frontDomain ?? undefined;
    this.natType = opts.natType ?? 'unknown';
    this.numRelayAddresses = opts.numRelayAddresses ?? 1;
  }

  /**
   * Send an SDP offer to the broker and receive a proxy's SDP answer.
   * This initiates the WebRTC rendezvous process.
   *
   * @param sdpOffer - The SDP offer string from RTCPeerConnection.createOffer()
   * @returns The broker's response containing the proxy's SDP answer
   */
  async negotiate(sdpOffer: string): Promise<BrokerAnswer> {
    // Build the request body following Snowflake broker protocol
    const body = JSON.stringify({
      Sid: generateSessionId(),
      Offer: sdpOffer,
      NatType: this.natType,
      Fingerprint: '', // Empty for clients
      RelayFingerprint: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // Required for broker
      RelayAddr: '', // Let broker choose relay
    });

    // Determine target URL (apply domain fronting if configured)
    const targetUrl = new URL('/client', this.brokerUrl);
    const fetchUrl = this.frontDomain
      ? new URL('/client', `https://${this.frontDomain}/`)
      : targetUrl;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // For domain fronting, set Host header to actual broker domain
    if (this.frontDomain) {
      headers['Host'] = new URL(this.brokerUrl).host;
    }

    const response = await fetch(fetchUrl.toString(), {
      method: 'POST',
      headers,
      body,
    });

    if (!response.ok) {
      throw new Error(`Broker request failed: ${response.status} ${response.statusText}`);
    }

    const text = await response.text();

    // The broker returns plain SDP answer text, or an error message
    // Check for common error patterns
    if (text.startsWith('no')) {
      // "no proxies available" or similar
      return { answer: '', error: text };
    }

    if (!text.includes('v=0') && !text.includes('a=ice')) {
      // Doesn't look like SDP, treat as error
      return { answer: '', error: text };
    }

    return { answer: text };
  }
}

/**
 * Generate a unique session ID for broker communication.
 * This helps the broker track client sessions.
 */
function generateSessionId(): string {
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto !== 'undefined') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    // Node.js fallback
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require('crypto').randomFillSync(bytes);
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
