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
   * Defaults to the Tor Project's production broker via Fastly CDN.
   */
  brokerUrl?: string;

  /**
   * Front domain for domain fronting.
   * When set, requests go through the front domain for censorship resistance.
   * Defaults to Fastly CDN (cdn.sstatic.net) matching the Snowflake browser extension.
   */
  frontDomain?: string;

  /**
   * Disable domain fronting (use direct broker connection).
   * Default: false (domain fronting enabled)
   */
  disableDomainFronting?: boolean;

  /**
   * NAT type reported to broker.
   * 'unknown' is the default and works for most cases.
   */
  natType?: 'unknown' | 'unrestricted' | 'restricted';

  /**
   * Bridge fingerprint to connect to.
   * Defaults to the original Snowflake bridge fingerprint.
   */
  bridgeFingerprint?: string;
};

export type BrokerAnswer = {
  /** The SDP answer from the proxy */
  answer: string;
  /** Error message if any */
  error?: string;
};

// Protocol version for client-broker communication
const CLIENT_VERSION = '1.0';

// Default broker URL (Tor Project's Snowflake broker)
const DEFAULT_BROKER_URL = 'https://snowflake-broker.torproject.net/';

// Default front domain for domain fronting (Fastly CDN, same as Snowflake browser extension)
// This is StackExchange's CDN which fronts through Fastly
const DEFAULT_FRONT_DOMAIN = 'cdn.sstatic.net';

// Default bridge fingerprint (the original Snowflake bridge)
// Used when client doesn't specify a fingerprint
const DEFAULT_BRIDGE_FINGERPRINT = '2B280B23E1107BB62ABFC40DDCC8824814F80A72';

/**
 * Client for the Snowflake broker rendezvous service.
 * Handles signaling between Snowflake clients and volunteer proxies.
 *
 * By default, uses domain fronting through Fastly CDN (cdn.sstatic.net)
 * matching the configuration of the Snowflake browser extension.
 *
 * Protocol compatible with Snowflake v1.0 client-broker protocol.
 */
export class SnowflakeBrokerClient {
  readonly brokerUrl: string;
  readonly frontDomain: string | undefined;
  readonly natType: string;
  readonly bridgeFingerprint: string;

  constructor(opts: BrokerClientOptions = {}) {
    this.brokerUrl = opts.brokerUrl ?? DEFAULT_BROKER_URL;
    // Enable domain fronting by default (matching Snowflake browser extension)
    this.frontDomain = opts.disableDomainFronting
      ? undefined
      : (opts.frontDomain ?? DEFAULT_FRONT_DOMAIN);
    this.natType = opts.natType ?? 'unknown';
    this.bridgeFingerprint = opts.bridgeFingerprint ?? DEFAULT_BRIDGE_FINGERPRINT;
  }

  /**
   * Send an SDP offer to the broker and receive a proxy's SDP answer.
   * This initiates the WebRTC rendezvous process.
   *
   * Uses the Snowflake v1.0 client-broker protocol:
   * Request: `1.0\n{"offer": "...", "nat": "...", "fingerprint": "..."}`
   * Response: `{"answer": "...", "error": "..."}`
   *
   * @param sdpOffer - The SDP offer string from RTCPeerConnection.createOffer()
   * @returns The broker's response containing the proxy's SDP answer
   */
  async negotiate(sdpOffer: string): Promise<BrokerAnswer> {
    // Build the request body following Snowflake v1.0 protocol
    // Format: version + newline + JSON body
    const pollRequest = {
      offer: sdpOffer,
      nat: this.natType,
      fingerprint: this.bridgeFingerprint,
    };
    const body = CLIENT_VERSION + '\n' + JSON.stringify(pollRequest);

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

    // Parse the JSON response
    try {
      const pollResponse = JSON.parse(text) as { answer?: string; error?: string };

      if (pollResponse.error) {
        return { answer: '', error: pollResponse.error };
      }

      if (pollResponse.answer) {
        return { answer: pollResponse.answer };
      }

      return { answer: '', error: 'received empty broker response' };
    } catch {
      // Fallback: old-style plain text response
      if (text.startsWith('no')) {
        return { answer: '', error: text };
      }
      if (!text.includes('v=0') && !text.includes('a=ice')) {
        return { answer: '', error: text };
      }
      return { answer: text };
    }
  }
}
