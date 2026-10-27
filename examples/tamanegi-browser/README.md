# TamanegiBrowser

A static website that uses Snowflake to browse web pages through Tor entirely
in the browser. ("Tamanegi" 🧅 is Japanese for "onion".)

## Features

- **Pure Browser Implementation**: No server-side component required
- **Snowflake Transport**: Uses the WebSocket-based Snowflake pluggable transport
- **3-Hop Tor Circuit**: Builds a proper Tor circuit through entry, middle, and exit nodes
- **Visual Circuit Display**: Shows the path your traffic takes through the Tor network
- **Live Connection Log**: Real-time status updates during connection and fetching

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser tab                             │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐   │
│  │  UI Layer   │───▶│  Tor client  │───▶│  Snowflake stack  │   │
│  │  (Vite)     │    │  (circuit)   │    │  (WS+KCP+SMUX)    │   │
│  └─────────────┘    └──────────────┘    └───────────────────┘   │
│                            │                      │             │
│                     ┌──────┴──────┐               │             │
│                     │  TLS 1.3    │               │             │
│                     └─────────────┘               │             │
└───────────────────────────────────────────────────┼─────────────┘
                                                    │
                                          WebSocket connection
                                                    │
                                                    ▼
                                     ┌──────────────────────────┐
                                     │  Snowflake relay (WSS)   │
                                     │ snowflake.torproject.net │
                                     └──────────────────────────┘
                                                    │
                                                    ▼
                                         ┌──────────────────┐
                                         │   Tor network    │
                                         │  (3-hop circuit) │
                                         └──────────────────┘
```

This page is glue: it plugs the `browser` package's Tor + Snowflake stack
into a Vite app, drives a 3-hop circuit, and renders fetched HTML in an
iframe via `srcdoc`. The interesting protocol work — the full Snowflake
client, KCP, SMUX, the Tor channel — lives in the workspace packages,
not here. For the layer-by-layer breakdown see
[`packages/browser/README.md`](../../packages/browser/README.md).

## How it works

1. **Snowflake connection**: Connect to the Tor network via a Snowflake WebSocket relay
2. **TLS 1.3**: Use `@reclaimprotocol/tls` for TLS 1.3 inside the browser
3. **Circuit building**: Extend the circuit through randomly selected middle and exit nodes
4. **HTTP fetching**: Construct raw HTTP/1.1 requests over the Tor circuit
5. **Content display**: Inject the fetched HTML into an iframe using `srcdoc`

## Limitations

- **External resources**: Images, CSS and JavaScript from external origins won't load automatically (each would need its own Tor fetch)
- **JavaScript execution**: Dynamic page content that requires JavaScript may not work correctly
- **CORS/CSP**: Some pages have restrictions that prevent proper display
- **Performance**: Tor routing adds latency; expect slower page loads

## Development

```bash
# Install dependencies (from repo root)
yarn install

# Start development server
cd examples/tamanegi-browser
yarn dev
```

The development server starts at `http://localhost:3000`.

## Mainnet onion smoke test

Test the production build, including its service worker, from the repository root:

```bash
yarn workspace tamanegi-browser build
yarn workspace tamanegi-browser preview --host 127.0.0.1 --port 4317 --strictPort
```

Open `http://127.0.0.1:4317/` and enter
`http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/`
in Tamanegi's address field. Confirm that the connection log reaches
`Connected to hidden service!`, reports a received response, and displays the
Tor Project page. Then press **Go** again without reloading Tamanegi to check
that a completed request leaves the shared connection usable.

The first run downloads consensus and relay information; later requests can use
the browser's cached directory data. Record those separately when comparing
timings. Live mainnet availability is independent of the deterministic Chutney
tests in CI.

## Security notes

- This is a proof-of-concept / educational tool
- Certificate validation is relaxed for compatibility (Tor relays are self-signed; identity is checked later via the Tor CERTS cell)
- The Tor circuit provides anonymity for your browsing
- External resources not loaded through Tor may leak information
