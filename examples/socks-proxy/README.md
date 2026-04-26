# SOCKS5 proxy server over Tor

Runnable Node.js demo that bootstraps a 3-hop Tor circuit on the live
network and exposes it as a SOCKS5 proxy on `localhost:1080`. Any
SOCKS5-aware client (curl, browsers, scripts, language SDKs) can plug
in without linking against `tor`.

The implementation lives in [`packages/tor`](../../packages/tor) — see
`SocksProxyServer` exported from `tor/socks`. This example is just the
~100-line driver.

## Run

```bash
yarn workspace tor-example-socks-proxy start
```

The first request takes the longest because the circuit has to bootstrap.
Subsequent requests reuse the same circuit until you Ctrl-C.

## Try it

Once `SOCKS5 proxy listening on 127.0.0.1:1080` shows up:

```bash
# Forward DNS via the exit (no local DNS leak — that's what
# `--socks5-hostname` enforces, vs. plain `--socks5`).
curl --socks5-hostname localhost:1080 https://check.torproject.org

# Anonymous DNS over the circuit (Tor proposal 100 RESOLVE):
curl --socks5-hostname localhost:1080 -v http://example.com 2>&1 | head -20
```

## How it works

1. `retryTransient(connectRandomCircuitWithSafeBootstrap)` builds a
   3-hop circuit, retrying transient bootstrap failures (fallback dir
   ECONNREFUSED, guard timeouts, etc.).
2. `new SocksProxyServer({ circuit, port, host })` wraps a Node TCP
   listener that speaks SOCKS5 and bridges each accepted client onto
   the circuit. Supported commands:
   - `CONNECT` — TCP-shaped streams to IPv4/IPv6/domain destinations.
   - `RESOLVE` (0xF0) and `RESOLVE_PTR` (0xF1) — anonymous DNS over the
     circuit (Tor proposal 100).
3. `USERNAME_PASSWORD` (RFC 1929) is accepted as a stream-isolation
   key per c-tor / Arti convention. The default config doesn't act on
   it — see `circuitFactory` in `SocksProxyServer` for how to give
   each isolation key its own circuit.

## Stopping

Ctrl-C (`SIGINT`) or `SIGTERM` triggers a graceful shutdown that
destroys active client sockets, the SOCKS listener, and the circuit
in that order so any in-flight stream receives a clean RELAY_END.
