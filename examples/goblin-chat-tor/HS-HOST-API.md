# HS-host API contract

Concrete requirements that the inflight `claude/tor-hidden-services-sDXWN`
branch must satisfy for the [goblin-chat-tor](./README.md) example to work in
the browser.

This is a **review checklist for the HS-host branch author**, not a finished
design. Items 1–8 below are blocking; 9–10 are strongly preferred.

---

## 1. Public API

Single entry point, browser-callable, returning a long-lived host handle:

```ts
export type PublishHiddenServiceOptions = {
  torClient: TorClient;                       // browser or node TorClient
  port: number;                                // virtual port on the .onion
  onConnection: (stream: CircuitStream) => void;
  identityKey?: Ed25519PrivateKeyBytes;        // 32-byte seed; restore .onion
  numIntroPoints?: number;                     // default 3
  descriptorLifetimeMs?: number;               // default per spec
  log?: (msg: string) => void;
};

export type HsHost = {
  readonly onion: string;                      // 56-char-base32 + ".onion"
  readonly identityKey: Ed25519PrivateKeyBytes; // raw seed for persistence
  readonly numActiveIntroPoints: () => number;
  unpublish(): Promise<void>;
};

export function publishHiddenService(
  opts: PublishHiddenServiceOptions
): Promise<HsHost>;
```

Notes
- `Ed25519PrivateKeyBytes` is the raw 32-byte seed (compatible with
  `tor-crypto`'s ed25519 keygen). No PEM, no Buffer-only types.
- `CircuitStream` is the existing `tor/relay-cell.ts` / `tor/circuit.ts`
  stream type used by `connectToHiddenService` — same readable/writable
  surface so the netlayer treats inbound and outbound symmetrically.

## 2. Browser portability constraints

- No `node:net`, `node:dgram`, `node:fs`, `node:tls`, `node:http` outside the
  `packages/browser/src/shims/` aliases already used by `tamanegi-browser`.
- All circuit-building goes through `torClient` (which already abstracts
  Node TLS vs Snowflake).
- All TLS is `@reclaimprotocol/tls` via the browser shim — same as the rest
  of the stack.
- All randomness is `tor-crypto` (already isomorphic).

## 3. Identity / persistence

- `identityKey` (input) restores the same `.onion` from a previous run.
- `identityKey` (output) on the returned host is the **same** seed the caller
  passed in, or the freshly generated one if none was passed.
- The example will store this in IndexedDB; the HS-host branch is **not**
  responsible for storage, only for round-tripping bytes.
- Generation uses ed25519 keygen from `tor-crypto`. Master identity key,
  blinded keys, and descriptor-signing keys all derived per rend-spec-v3.

## 4. Server-side hs-ntor + descriptor pipeline

The branch must add (currently absent in tor-ts; only the client side exists
in `hidden-service.ts`):

- **Server-side hs-ntor** handshake (rend-spec-v3 §3.3.2) — derive
  `KEYS_TARGET` from incoming `INTRODUCE2`, validate `MAC`, produce circuit
  keys for the rendezvous circuit.
- **Descriptor build + sign** — outer + inner layers, blinded signing key for
  the current time period, encrypted with subcredential, padded per spec.
- **HSDir upload** — symmetric to the existing `selectHsdirsForFetch` /
  fetch flow in `hidden-service.ts`. POST descriptor to selected HSDirs over
  directory circuits built via `torClient`.
- **Intro-point selection + ESTABLISH_INTRO** — pick relays with `Stable` and
  no `BadExit`, build intro circuits, send `ESTABLISH_INTRO` cells, await
  `INTRO_ESTABLISHED`.
- **INTRODUCE2 handler** — on each `INTRODUCE2` from an active intro circuit:
  parse, verify, do server-side hs-ntor, build the rendezvous circuit to the
  client-chosen RP, send `RENDEZVOUS1`, then accept `BEGIN` cells on the
  resulting circuit and yield each as a `CircuitStream` to `onConnection`.

## 5. Lifecycle

| Stage | Expected behavior |
|---|---|
| `publishHiddenService(...)` returns | `numActiveIntroPoints() ≥ 1`, descriptor uploaded to ≥1 HSDir, `.onion` reachable. May return before all intro points are up; a `whenReady()` promise is acceptable but optional. |
| Steady state | Intro circuits maintained at the configured count; if one dies, replace it within seconds. Republish descriptor at least once per descriptor lifetime, and on intro-point churn. |
| `unpublish()` | Tear down all intro circuits, stop republish timer, resolve. After resolution no further `onConnection` calls fire. Idempotent. |
| `torClient` shutdown | If the underlying client is destroyed, the host transitions to a terminal state and stops calling `onConnection`. No unhandled rejections. |

## 6. Concurrency

- Multiple `INTRODUCE2`s arriving in parallel must each produce their own
  rendezvous circuit and their own `CircuitStream`. No serialization, no
  shared mutable state in the hot path.
- A single rendezvous circuit may carry multiple `BEGIN` streams (per
  rend-spec-v3) — each must surface as a separate `onConnection(stream)`
  call.
- Backpressure: if `onConnection` throws or the consumer is slow,
  individual streams may stall, but other streams and the host as a whole
  must keep functioning.

## 7. Long-lived operation in a service worker

The example will run the host inside a service worker (mirroring
`tamanegi-browser/src/sw.ts`). The HS-host implementation must:

- Use no global `setInterval` that the platform can throttle into uselessness
  on hidden tabs without recovery — descriptor republish must catch up after
  a long pause.
- Tolerate the underlying `SnowflakeBrowserChannel` reconnecting; intro
  circuits will need to be rebuilt on top of a fresh channel.
- Avoid retaining references that prevent the worker from being terminated
  cleanly when `unpublish()` is called.

## 8. Errors

- `publishHiddenService` rejects only on unrecoverable startup errors
  (e.g. all intro-point candidates exhausted, all HSDir uploads failed
  after retry). Transient failures inside the host (one intro circuit
  dies, one HSDir upload 5xx's) are handled internally and surfaced via
  `log` only.
- `unpublish()` never rejects.
- Errors during `onConnection` callbacks are logged and swallowed — they
  don't poison the host.

## 9. Testing surface

The branch should land with:

- Unit tests for descriptor build/sign + parse round-trip (against existing
  parser in `hidden-service.ts`).
- Unit test for server-side hs-ntor against a known test vector.
- Integration test on chutney: `publishHiddenService` in one process,
  `connectToHiddenService` in another, exchange bytes both directions.
- Bonus: a browser-context test (vitest-browser or playwright) that does
  the same against chutney via Snowflake.

The example will add an end-to-end live test that chains both sides in the
same process to prove `connect`/`listen` symmetry.

## 10. Optional but valuable

- `host.onIntroPointChurn(cb)` — observable for UI ("3/3 intro points
  healthy").
- `host.republishDescriptor()` — manual trigger for diagnostics.
- `client-auth` (rend-spec-v3 §G) — out of scope for v1, but the API should
  not preclude adding it later (e.g. accept an optional `authorizedClients`
  field that's documented as unimplemented).

---

## Acceptance criteria for unblocking goblin-chat-tor

1. `publishHiddenService` exists with the signature in §1.
2. The accept callback yields `CircuitStream` instances usable directly with
   the existing `tor/circuit.ts` stream APIs.
3. `identityKey` round-trip is exact (same `.onion` on republish).
4. Two browser tabs, each on the live network, can bootstrap, publish their
   onion, exchange sturdyrefs out-of-band (paste-in URI), connect, and
   exchange OCapN frames in both directions for ≥60 seconds without circuit
   churn breaking the conversation.
5. `unpublish()` reliably stops the host and releases all circuits.
