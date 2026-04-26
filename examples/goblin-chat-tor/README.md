# goblin-chat-tor (planning)

A static webapp running [OCapN](https://github.com/endojs/endo/tree/master/packages/ocapn)
goblin-chat over a **custom Tor netlayer backed by tor-ts**, with **bidirectional**
peer-to-peer messaging directly between browser tabs — no Tor daemon, no SOCKS
proxy, no Node host.

This directory currently contains design documents only. Implementation is gated
on the prerequisites listed below.

## Reference

Architecturally equivalent to [endojs/endo#3197](https://github.com/endojs/endo/pull/3197),
but the daemon-backed netlayer is replaced with a tor-ts-native one that runs in
the browser.

## Architecture (Arch A only)

Two browser tabs each run the same static webapp. Each tab is **both an OCapN
client and an OCapN host** — every tab gets its own `.onion` and its own
sturdyrefs.

```
  Tab A                                  Tab B
  ┌────────────────────────┐             ┌────────────────────────┐
  │  goblin-chat UI        │             │  goblin-chat UI        │
  │  ─ ocapn client ───────│  Tor HS     │── ocapn client ─       │
  │  ─ ocapn netlayer ─────│ ────────► ◄ │── ocapn netlayer ──    │
  │     (custom, tor-ts)   │  rendezvous │     (custom, tor-ts)   │
  │  ─ TorClient (browser) │             │── TorClient (browser)  │
  │  ─ Snowflake channel ──│             │── Snowflake channel ─  │
  └────────────────────────┘             └────────────────────────┘
```

**Outbound** (`netlayer.connect(loc)`):
`torClient.connectToHiddenService(loc.designator, port)` → `CircuitStream` →
OCapN frames.

**Inbound** (`netlayer.listen()`):
`publishHiddenService({ torClient, port, onConnection })` from the inflight
HS-host code; `onConnection(stream)` hands each rendezvous stream to OCapN's
`handlers.onIncoming(stream)`.

The same `TorClient` instance backs both directions. `connectToHiddenService` is
already browser-callable on tor-ts `main`.

## File layout (planned)

```
examples/goblin-chat-tor/
  README.md                  # this file
  HS-HOST-API.md             # API contract the inflight HS-host branch must satisfy
  package.json               # tor, browser, @endo/ocapn, @endo/goblin-chat, vite
  vite.config.ts             # mirrors tamanegi-browser shims/aliases
  index.html
  src/
    main.ts                  # boots TorClient, wires netlayer, runs chat
    netlayer-tor-ts.ts       # makeTorTsNetLayer({ torClient, hsHost, logger })
    chat-ui.ts               # sturdyref input, send box, message log
    sturdyref.ts             # parse/format ocapn:// URIs
    hs-identity-store.ts     # IndexedDB-backed Ed25519 HS identity persistence
    sw.ts                    # service worker hosting long-lived intro circuits
    styles.css
  test/
    netlayer.spec.ts         # unit: framing, connect/listen mocks
    interop.live.spec.ts     # live (chutney + HS host) bidirectional ping
```

## Prerequisites and what each must deliver

### `claude/tor-hidden-services-sDXWN` — HS host (**critical blocker**)

Detailed contract in [HS-HOST-API.md](./HS-HOST-API.md). Summary:

- Browser-shaped exports — no `node:net` / `node:dgram` / `node:fs` / `node:tls`
  outside the existing `packages/browser/src/shims/` aliases. Must ride
  `TorClient` + `Circuit` + `ChannelManager` like the client side does.
- `publishHiddenService({ torClient, identityKey?, port, onConnection })`
  returning `{ onion, identityKey, unpublish() }`.
- Persistable Ed25519 identity (raw bytes round-trip) so the same `.onion` can
  be republished across reloads.
- Server-side hs-ntor (rend-spec-v3 §3.3), INTRODUCE2 parsing, RENDEZVOUS1
  emission, descriptor upload to selected HSDirs.
- Long-lived intro-circuit pool (≥3 circuits) with periodic descriptor
  republish — must work in a service worker.
- Concurrent rendezvous — multiple inbound peers introduce in parallel, each
  produces its own `CircuitStream`.
- Honest `unpublish()` — tears down intro circuits and stops republishing.

### `claude/socks-proxy-tor-SRS33` — SOCKS proxy (**out of scope**)

Architecture A does not use SOCKS. The netlayer dials tor-ts circuits directly.
Tracking removed from this project's blockers.

### OCapN on npm

- Netlayer registration (`client.registerNetlayer(...)` per endo PR #3197) must
  be reachable from a browser bundle.
- Sturdyref helpers (`makeSturdyRef`, `enlivenSturdyRef`, `parseSturdyrefUri`)
  must be browser-callable.
- `runChatParticipant` (or the underlying chatroom interface) must be free of
  Node-only imports. The goblin-chat test harness in PR #3197 lives under
  `test/guile-interop` and may pull in `node:fs` / `node:child_process`; we
  likely vendor a slim `chat-participant.ts` from the lib path rather than the
  test path.
- Stream contract — whatever shape OCapN's netlayer expects (async iterator
  pair? Node `Duplex`?), tor-ts `CircuitStream` either matches or we adapter
  it. Pin once a published version is in hand.

If ocapn isn't on npm with these properties when we're ready to build:
1. `pkg.pr.new` build of the PR branch, or
2. fork + publish under a scoped name, or
3. vendor the netlayer interface + sturdyref + chat helpers into the example.

### tor-ts itself (in our court, non-blocking)

- `openHsStream(onion, port)` convenience on the browser `TorClient` — current
  `connectToHiddenService` returns circuit + intro-points + destroy; we want a
  plain `CircuitStream`.
- IndexedDB-backed HS-identity store in `packages/browser`, analogous to
  `LocalStorageMicrodescStorage`.
- Confirm the `tamanegi-browser` service-worker pattern is compatible with the
  HS-host intro-circuit refresh loop.

## Need ranking

| # | Need | Owner | Blocker? |
|---|---|---|---|
| 1 | Browser-shaped HS host with `publish()` accept-callback API | `claude/tor-hidden-services-sDXWN` | **yes** |
| 2 | Persistable Ed25519 HS identity | `claude/tor-hidden-services-sDXWN` | yes (usable chat) |
| 3 | Server-side hs-ntor + INTRODUCE2 + descriptor upload | `claude/tor-hidden-services-sDXWN` | yes |
| 4 | OCapN netlayer registration in browser bundle | ocapn npm | **yes** |
| 5 | Browser-clean `runChatParticipant`-equivalent | ocapn / goblin-chat npm | yes (or vendor) |
| 6 | Long-lived intro-circuit refresh inside service worker | tor-ts + HS-host branch | yes (tab backgrounding) |
| 7 | IndexedDB store for HS identity | tor-ts browser package | yes (stable `.onion`) |
| 8 | `openHsStream(onion, port)` convenience on browser TorClient | tor-ts | nice-to-have |
| 9 | SOCKS proxy | `claude/socks-proxy-tor-SRS33` | **no** (out of scope) |

## Open questions

- **Service-worker lifetime vs. HS uptime.** A service worker can be evicted
  while the page is backgrounded; if our intro circuits live there, the
  `.onion` goes silent. Tab-only hosting means the chat is reachable only while
  at least one peer keeps the page open. Acceptable for v1, but worth calling
  out in the UI.
- **Bootstrap latency.** Snowflake bootstrap + HSDir publish + 3 intro circuits
  is many seconds before the tab is reachable. UI needs a clear "publishing
  your onion…" state.
- **Cross-tab key reuse.** If the user opens two tabs of the app on the same
  origin, do they share an identity (one `.onion`, two clients) or get
  separate ones? IndexedDB is shared across same-origin tabs, so default is
  shared; document this.
- **NAT / Snowflake reliability.** Hosting an HS over Snowflake is novel — the
  upstream channel has to stay up far longer than for one-shot fetches in
  `tamanegi-browser`. May surface bugs in `packages/snowflake`.
