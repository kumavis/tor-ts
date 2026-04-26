### dragons 🐉

⚠️ _don't use this for anything important!_

This has **not** been audited, skips some security precautions, and is likely
highly fingerprintable. It is for educational and experimental purposes only.

### tor-ts 🧅

A TypeScript implementation of the [Tor anonymization and anti-censorship
protocol](https://www.torproject.org/), runnable in Node.js or directly in a
browser tab via [Snowflake](https://snowflake.torproject.org/).

The repo is a yarn workspace. Each package is independently published-shaped
and tested; the examples wire them together for concrete use cases.

#### Status

Implemented:

- [x] Client circuit to clearweb (3-hop ntor + relay cells)
- [x] Client circuit to v3 hidden services (rend-spec-v3, INTRODUCE/RENDEZVOUS, hs-ntor)
- [x] **Hosting v3 hidden services (server side: ESTABLISH_INTRO with KH-bound MAC, descriptor build/sign/publish, INTRODUCE2 decrypt, hs-ntor server, rendezvous virtual hop)**
- [x] Browser support via Snowflake (WSS → turbotunnel → KCP → SMUX → TLS 1.3 → Tor)
- [x] Signed-consensus verification (against the hardcoded mainnet authorities; injectable trust anchor for chutney/test nets)
- [x] Bandwidth-weighted relay selection with exit-policy filtering
- [x] CI integration tests against the live Tor network and a local [chutney](https://gitlab.torproject.org/tpo/core/chutney) test net
- [x] SOCKS5 proxy server (`SocksProxyServer`) that fronts arbitrary clients with a Tor circuit; supports CONNECT to IPv4/IPv6/domain targets

Not implemented:

- [ ] Guard / middle / exit relay (this is a client-only stack)
- [ ] Directory authority

### Packages

- [`packages/tor`](./packages/tor) — the Tor protocol implementation:
  cells, circuits, link/relay protocols, ntor handshake, directory client,
  consensus parsing+verification, hidden-service client + server. Standalone
  in Node.js with a TLS channel; the entry point most users want is
  `connectRandomCircuitWithSafeBootstrap()` from
  [`packages/tor/src/build-circuit/mainnet.ts`](./packages/tor/src/build-circuit/mainnet.ts).
  To host an onion service, the entry point is `publishHiddenService(...)`
  in [`packages/tor/src/hidden-service-host.ts`](./packages/tor/src/hidden-service-host.ts) —
  takes any bootstrapped `TorClient` (mainnet, chutney, or browser/Snowflake)
  and surfaces inbound BEGIN-streams via an `onConnection` callback.
- [`packages/snowflake`](./packages/snowflake) — the client side of the
  [Snowflake](https://snowflake.torproject.org/) pluggable transport in pure
  TypeScript: encapsulation framing, turbotunnel preamble,
  [KCP](https://github.com/skywind3000/kcp) reliable-over-packet, and
  [SMUX](https://github.com/xtaci/smux) v2 multiplexing. As far as we know,
  this is the second client implementation of the Snowflake stack anywhere
  (the canonical Go client being the first; Arti shells out to it).
- [`packages/browser`](./packages/browser) — browser glue that composes
  Snowflake + Tor into a single TLS-1.3-capable channel that runs entirely
  in a tab or service worker, using
  [`@reclaimprotocol/tls`](https://github.com/reclaimprotocol/reclaim-tls).
  Layer-by-layer protocol stack documented in
  [`packages/browser/README.md`](./packages/browser/README.md).
- [`packages/crypto`](./packages/crypto) — `tor-crypto`: the small set of
  primitives Tor needs (Curve25519, Ed25519, AES-CTR, SHA-1/2/3, HKDF,
  PKCS#1 RSA verify), with isomorphic Node and browser entry points.

### Examples

- [`examples/tamanegi-browser`](./examples/tamanegi-browser) — Vite static
  site that browses the web through Tor entirely from a browser tab via
  Snowflake. ("Tamanegi" 🧅 is Japanese for "onion".) The HTML it fetches
  renders inside an `<iframe srcdoc>`.
- [`examples/node-fetch`](./examples/node-fetch) — minimal Node script that
  does an HTTPS request through a 3-hop Tor circuit using `node-fetch` and
  the `tor` package's HTTP agent.
- [`examples/http-proxy`](./examples/http-proxy) — local HTTP proxy server
  that fronts arbitrary clients with a Tor circuit per upstream connection.
  Useful for plugging existing tooling (curl, browsers, scripts) into the
  in-process Tor stack without changing them.

### Development

```bash
# install deps (yarn 4 via corepack)
yarn install

# run the unit test suite (every package)
yarn test

# typecheck everything
yarn typecheck

# format + lint
yarn format
yarn lint

# live integration tests (require network access; chutney tests
# additionally need a local chutney install — see packages/tor/scripts/ci-chutney.sh)
yarn test:live
```
