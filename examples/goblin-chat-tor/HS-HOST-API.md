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
  torClient: TorClient; // browser or node TorClient
  port: number; // virtual port on the .onion
  onConnection: (stream: CircuitStream) => void;
  identityKey?: Ed25519PrivateKeyBytes; // 32-byte seed; restore .onion
  numIntroPoints?: number; // default 3
  descriptorLifetimeMs?: number; // default per spec
  log?: (msg: string) => void;
};

export type HsHost = {
  readonly onion: string; // 56-char-base32 + ".onion"
  readonly identityKey: Ed25519PrivateKeyBytes; // raw seed for persistence
  readonly numActiveIntroPoints: () => number;
  unpublish(): Promise<void>;
};

export function publishHiddenService(opts: PublishHiddenServiceOptions): Promise<HsHost>;
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

| Stage                               | Expected behavior                                                                                                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `publishHiddenService(...)` returns | `numActiveIntroPoints() ≥ 1`, descriptor uploaded to ≥1 HSDir, `.onion` reachable. May return before all intro points are up; a `whenReady()` promise is acceptable but optional. |
| Steady state                        | Intro circuits maintained at the configured count; if one dies, replace it within seconds. Republish descriptor at least once per descriptor lifetime, and on intro-point churn.  |
| `unpublish()`                       | Tear down all intro circuits, stop republish timer, resolve. After resolution no further `onConnection` calls fire. Idempotent.                                                   |
| `torClient` shutdown                | If the underlying client is destroyed, the host transitions to a terminal state and stops calling `onConnection`. No unhandled rejections.                                        |

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

---

## As-shipped audit (against `main` @ `c5c5519`)

The HS-host landed in `packages/tor/src/hidden-service-host.ts` and is
re-exported from `packages/tor/src/index.ts`. Quick pass against the
contract above:

| §   | Item                                                                                                  |  Shipped   | Notes                                                                                                                                                                                                                                                                          |
| --- | ----------------------------------------------------------------------------------------------------- | :--------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `publishHiddenService(opts) => Promise<HsHost>`                                                       |     ✅     | Signature matches, `HsHost` shape matches (`onion`, `identityKey`, `numActiveIntroPoints()`, `unpublish()`).                                                                                                                                                                   |
| 1   | `Ed25519PrivateKeyBytes` as raw 32-byte seed                                                          |     ✅     | Accepts `Buffer \| Uint8Array`, returns `Uint8Array`.                                                                                                                                                                                                                          |
| 1   | `CircuitStream` accept-callback yield type                                                            |     ✅     | `onConnection(stream: CircuitStream)`.                                                                                                                                                                                                                                         |
| 2   | Browser portability                                                                                   |     ✅     | No `node:net/tls/fs/dgram/http/crypto/stream/child_process/os/path`. Only Node-shaped import is `events`, which is shimmed by `vite-plugin-node-polyfills` and is `EventEmitter` in browsers. The file's docstring explicitly calls out service-worker compatibility.          |
| 3   | Identity persistence (round-trip seed → same `.onion`)                                                |     ✅     | `identityKey` in/out documented as "32-byte ed25519 seed that pins the .onion address".                                                                                                                                                                                        |
| 4   | Server-side hs-ntor + descriptor pipeline + INTRODUCE2 + ESTABLISH_INTRO + HSDir upload               |     ✅     | All five exports present (`completeHsNtorServer`, `generateDescriptor`, `parseIntroduce2`, `decryptIntroduce2`, `buildEstablishIntroPayload`). Chutney CI exercises end-to-end.                                                                                                |
| 5   | Lifecycle (publish resolves once IP up + descriptor uploaded; `unpublish` idempotent + non-rejecting) |     ✅     | Documented: "Resolves once at least one introduction point is established AND the descriptor has been uploaded to at least one HSDir … `unpublish()` is idempotent and never rejects."                                                                                         |
| 5   | Steady-state intro-circuit refresh + descriptor republish                                             |     ✅     | `descriptorRefreshMs` (default 30 min), intro-point churn watchdog (commit `157ee9f`).                                                                                                                                                                                         |
| 6   | Concurrent rendezvous → independent streams per BEGIN                                                 |     ✅     | Per-stream `onConnection` callback; multi-port via `port: number \| number[]` is a bonus over the contract.                                                                                                                                                                    |
| 7   | Service-worker viability                                                                              |     ⚠️     | Asserted in source comments; not yet demonstrated end-to-end under tab-backgrounding. The goblin-chat-tor example is the first user.                                                                                                                                           |
| 8   | Errors only via `log` in steady state                                                                 |     ✅     | Documented: "Errors during steady state … are surfaced via `log` only — they don't reject the original promise or escape."                                                                                                                                                     |
| 9   | Unit tests + chutney integration                                                                      |     ✅     | `hidden-service-host.spec.ts` plus `scripts/chutney-hidden-service-host-ci.ts`, enabled in CI as of `a5d07e4`.                                                                                                                                                                 |
| 10  | Optional: `host.onIntroPointChurn` observable                                                         | ➕ partial | `HiddenServiceHost extends EventEmitter` with `'introduce2-error'`, `'rendezvous'`, `'connection'`, `'stopped'` events. The high-level `HsHost` returned by `publishHiddenService` does not surface the EE; if the example wants it, instantiate `HiddenServiceHost` directly. |

**Bonus features beyond the contract** (worth knowing about):

- Multi-port: `port: number \| number[]` accepts BEGIN cells for any listed port.
- Custom `acceptPort: (port: number) => boolean` for wildcard / dynamic services.
- `perStepTimeoutMs` for per-handshake timeouts.
- `numActiveIntroPoints()` accessor on `HsHost`.

**Minor gaps** (non-blocking, tracked in [README.md](./README.md) need ranking):

- `packages/browser/src/index.ts` does not re-export `publishHiddenService`.
  Works via `import { publishHiddenService } from 'tor'` but a browser-package
  re-export would mirror the existing `connectToHiddenService` ergonomics.
- High-level `HsHost` doesn't expose the underlying `EventEmitter`. Fine for v1.

This contract is **considered satisfied for the purposes of unblocking
goblin-chat-tor**. Any further work is on the OCapN side or in the example
itself.
