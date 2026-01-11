# Browser-in-Browser Tor Proxy

A static website that uses Snowflake to browse web pages through Tor entirely in the browser.

## Features

- **Pure Browser Implementation**: No server-side component required
- **Snowflake Transport**: Uses WebSocket-based Snowflake pluggable transport
- **3-Hop Tor Circuit**: Builds a proper Tor circuit through entry, middle, and exit nodes
- **Visual Circuit Display**: Shows the path your traffic takes through the Tor network
- **Live Connection Log**: Real-time status updates during connection and fetching

## How It Works

1. **Snowflake Connection**: Connects to the Tor network via a Snowflake WebSocket relay
2. **TLS 1.3**: Uses @reclaimprotocol/tls for TLS 1.3 encryption in the browser
3. **Circuit Building**: Extends the circuit through randomly selected middle and exit nodes
4. **HTTP Fetching**: Constructs raw HTTP/1.1 requests over the Tor circuit
5. **Content Display**: Injects fetched HTML into an iframe using `srcdoc`

## Limitations

- **External Resources**: Images, CSS, and JavaScript from external sources won't load automatically (they would need additional Tor fetches)
- **JavaScript Execution**: Dynamic page content that requires JavaScript may not work correctly
- **CORS/CSP**: Some pages may have restrictions that prevent proper display
- **Performance**: Tor routing adds latency; expect slower page loads

## Development

```bash
# Install dependencies (from repo root)
yarn install

# Start development server
cd examples/browser-proxy
yarn dev
```

The development server will start at `http://localhost:3000`.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │  UI Layer   │───▶│  Tor Client  │───▶│  Snowflake Stack  │  │
│  │  (Vite)     │    │  (Circuit)   │    │  (WS + KCP + SMUX)│  │
│  └─────────────┘    └──────────────┘    └───────────────────┘  │
│                            │                      │              │
│                     ┌──────┴──────┐               │              │
│                     │  TLS 1.3    │               │              │
│                     └─────────────┘               │              │
└───────────────────────────────────────────────────│──────────────┘
                                                    │
                                           WebSocket Connection
                                                    │
                                                    ▼
                                     ┌──────────────────────────┐
                                     │  Snowflake Relay (WSS)   │
                                     │  snowflake.torproject.net│
                                     └──────────────────────────┘
                                                    │
                                                    ▼
                                         ┌──────────────────┐
                                         │   Tor Network    │
                                         │  (3-hop circuit) │
                                         └──────────────────┘
```

## Security Notes

- This is a proof-of-concept/educational tool
- Certificate validation is relaxed for compatibility
- The Tor circuit provides anonymity for your browsing
- External resources not loaded through Tor may leak information
