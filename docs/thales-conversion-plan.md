# Thales conversion plan

A roadmap for moving as much of `tor-ts` as possible into the
[Thales TypeScript subset](https://github.com/jessealama/thales/blob/main/docs/subset.md)
so it can be transpiled to Lean and (where annotated `@total`) checked for
totality and termination.

The goal is not 100% coverage — Tor is fundamentally a network stack of
sockets, timers, and events, none of which fit a pure/total subset. The goal
is to draw module-level seams so the **wire-format codecs, key-derivation
math, parsers, and protocol step-functions** can live inside Thales while a
thin imperative shell drives I/O.

## 1. What Thales rules out

From the v0.5 / v1.0 subset doc, the rules that bite this codebase are:

| Code          | Rule                                                                    | tor-ts impact                                                           |
| ------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| TH0001        | No `let` reassignment                                                   | Pervasive; ~all stateful classes                                        |
| TH0002–TH0004 | No array/object mutation, no `.push/.pop/.splice/.sort/.reverse`        | 181 mutating-method call sites                                          |
| TH0010        | No `for`/`while`/`do-while`                                             | 185 loop sites; many in parsers                                         |
| TH0012        | No `async`/`await`/`Promise`                                            | 543 hits in non-test code                                               |
| TH0020/TH0021 | No `any`/`unknown`                                                      | ~80 occurrences, mostly at FFI boundaries                               |
| TH0022        | Unions must be discriminated (`kind:` field)                            | Several string-literal unions need refactor                             |
| TH0023/TH0024 | No `&` intersections, `keyof`, conditional/mapped types                 | Sparse but present (e.g. `(typeof X)[keyof typeof X]`)                  |
| TH0030/TH0031 | No `class` / `extends`                                                  | 40+ class declarations, EventEmitter inheritance throughout             |
| TH0050/TH0070 | Termination must be provable (structural recursion or `@decreasing`)    | Most parsers walk byte buffers — fits `@decreasing` on remaining length |
| TH0060/TH0064 | `throw` requires `@throws` annotation; callers must catch or re-declare | Tractable; existing throws are mostly plain `Error`                     |

Effects Thales has no answer for at all:

- Timers (`setTimeout`, `setInterval`)
- RNG (`Math.random`, `crypto.randomBytes`, `crypto.getRandomValues`)
- Wall-clock (`Date.now()`)
- Sockets (`tls.connect`, `net.Socket`, `WebSocket`, `fetch`)
- Mutable byte buffers (`Buffer.alloc`, `buf.writeUIntBE`, `view.setUint32`)
- `EventEmitter` event dispatch

Anything that touches one of these must sit on the **outside** of the seam.

## 2. The general seam pattern

For every stateful subsystem we split into three layers:

```
┌──────────────────────────────────┐
│  Effect adapter (TS-only)        │  sockets, timers, EventEmitter,
│                                  │  Promises, RNG, wall-clock
├──────────────────────────────────┤
│  Wiring shim (TS-only, tiny)     │  buffers events into messages,
│                                  │  feeds them to step(), pushes
│                                  │  outputs back to the adapter
├──────────────────────────────────┤
│  Pure core (Thales-eligible)     │  type State, type Msg, type Out;
│                                  │  step(state, msg) -> { state, outs[] }
│                                  │  encoders, decoders, validators
└──────────────────────────────────┘
```

The pure core is the part that earns its keep in Lean: a mealy-machine style
`step` function plus encoders/decoders/validators is exactly the shape Thales
wants — total, terminating, deterministic given input.

The wiring shim is small and disposable; we don't try to verify it. Its only
job is to translate "socket got bytes" / "timer fired" / "user called close"
into discriminated-union `Msg` values, call `step`, and dispatch the outputs.

This is the exact shape `step` would take for, say, the link-layer channel:

```ts
type ChannelState = { /* immutable record */ };
type ChannelInput =
  | { kind: 'bytes'; data: ReadonlyArray<number> }
  | { kind: 'tick'; nowMs: bigint }
  | { kind: 'sendCell'; cell: MessageCell }
  | { kind: 'close' };
type ChannelOutput =
  | { kind: 'sendBytes'; data: ReadonlyArray<number> }
  | { kind: 'cellReceived'; cell: MessageCell }
  | { kind: 'armPaddingTimer'; deadlineMs: bigint }
  | { kind: 'closed'; reason: string };

/** @total */
function step(s: ChannelState, m: ChannelInput): { state: ChannelState; outs: ChannelOutput[] } { ... }
```

Termination follows from structural recursion on the byte buffer (with
`@decreasing` on `remaining.length` in the parsing helpers).

## 3. Cross-cutting design decisions

These three decisions ripple across every package and should be made up
front, because choosing wrong forces the wrong shape on every later module.

### 3.1 The `Bytes` type

`Buffer` is unusable inside Thales — it's a Node-only type, mutable, and its
read/write methods are not in the allowed stdlib. Pick one of:

- **(a)** `type Bytes = ReadonlyArray<number>` (each element 0–255). Plays
  cleanly with Thales (`Array T` in Lean, `.slice`, `.concat` are allowed).
  Adapters convert `Buffer ↔ number[]` at the seam. **Cost:** boxing /
  performance hit at the seam; loss of `DataView` ergonomics.
- **(b)** `type Bytes = Uint8Array` and treat it as immutable by convention,
  never calling mutating methods inside Thales code. **Risk:** Thales doesn't
  list `Uint8Array` in its stdlib, so this would require an `extern` Lean
  declaration and gives up on totality proofs of byte-level math.

**Recommendation: (a).** Performance does not matter for verification; we keep
performance-tuned `Uint8Array` paths in the impure shell. All Thales-side
encoders/decoders take and return `ReadonlyArray<number>`, with two seam
helpers `bufferToBytes` / `bytesToBuffer` living in TS-only adapter files.

### 3.2 Numbers: `number` vs `bigint`

Thales maps `number` to Lean `Float` and `bigint` to Lean `Int`. For
**byte-level** arithmetic (shifts, masks, BE/LE integer reads up to 32 bits)
`number` is wrong — `Float` does not give us bit-exact semantics. Use:

- `bigint` for all wire-level integer fields (cell lengths, sequence numbers,
  KCP `conv`/`sn`/`una`, ed25519 expirations, etc.). The codebase already
  uses `bigint` in hidden-service crypto; extend that discipline.
- `number` only for things that are genuinely real-valued (bandwidth weights,
  latency in seconds for selection). There are very few of these.

A small `bigint`-based `BytesReader` replaces the current Buffer-based one.

### 3.3 Effects as inputs

Pure step functions cannot read the clock or generate randomness. The fix is
the same in every case: pass the effectful values **in** as part of the input
message. The shell calls `Date.now()`/`randomBytes(n)` and packages them:

```ts
{ kind: 'tick', nowMs: 17345…n }
{ kind: 'genCircuitId', entropy: [0x4a, 0xb2, …] }
```

This converts `Math.random()`-style impurity into a data dependency, which
Thales handles fine.

## 4. Per-package landscape

Header legend:

- **PURE** — already pure or trivially so; convert as-is.
- **SPLIT** — currently mixed; refactor into pure core + thin adapter.
- **SHELL** — inherently effectful; stays out of Thales.

### 4.1 `packages/crypto` (~860 LOC)

| File                     | Verdict             | Notes                                                                                                                                                                                                                       |
| ------------------------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashes.ts`              | SHELL (FFI declare) | `sha256`, `sha3_256`, `shake256` are platform calls. Declare as Lean `extern`; Thales-side code calls them as opaque pure functions.                                                                                        |
| `curves.ts`              | SHELL (FFI declare) | Curve25519 / Ed25519 implementations bottom out in WebCrypto or Node `crypto`. Same FFI treatment.                                                                                                                          |
| `hs-crypto.ts`           | **PURE**            | `mac`, `dMac`, `bytesToBigIntLE`, `bigIntToBytesLE`, `modInverse`, `u64be` are bigint/byte math over the FFI hashes. The `Sha3_256Hash` class collapses to `type Sha3State = { acc: ReadonlyArray<number> }` + 3 functions. |
| `aes.ts`                 | SHELL               | Uses WebCrypto (async) and a `Mutex`. Pure block-counter math (`incrementCounter`) can be lifted into a tiny `aes-counter.ts` Thales module that produces the next counter buffer; the rest stays out.                      |
| `node.ts` / `browser.ts` | SHELL               | Platform glue.                                                                                                                                                                                                              |

**Yield:** ~250 LOC of `hs-crypto.ts` and a small slice of `aes.ts`
counter math become Thales-eligible. The rest is declared FFI.

### 4.2 `packages/tor` (~17.5k LOC)

#### Cleanly pure (PURE)

| File                     | LOC | Notes                                                                                                                                                                                                                                                   |
| ------------------------ | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `time.ts`                | 3   | Trivial; the `getTime` interface itself is a seam input.                                                                                                                                                                                                |
| `profiles.ts`            | 72  | Static config records.                                                                                                                                                                                                                                  |
| `fallback-dirs.ts`       | 150 | Compile-time data table.                                                                                                                                                                                                                                |
| `exit-policy.ts`         | 207 | Has one `for-of` loop; rewrite to `parts.map(...).filter(...)`. The `'accept'                                                                                                                                                                           | 'reject'`field needs to be promoted to a`kind:` discriminator (TH0022). |
| `http-parse.ts`          | 166 | Pure HTTP/1.1 line parser; rewrite the `for` loops as recursion over remaining lines.                                                                                                                                                                   |
| `relay-cell.ts`          | 464 | Encode/decode of relay-cell payloads. The single class (`RelayEndError extends Error`) becomes a discriminated-union `Result` return. The `as const` keyed lookup tables either stay (Thales allows `as const` records) or get inlined into a `switch`. |
| `messaging.ts`           | 858 | The largest pure island. All cell parsing/serialization is referentially transparent. The Buffer-based dispatch tables (`Record<number, fn>`) flatten to discriminated-union `switch` (TH0024). The current `assert` calls become `@throws Error`.      |
| `ntor.ts`                | 265 | Pure handshake math built on tor-crypto FFI.                                                                                                                                                                                                            |
| `cert.ts`                | 600 | Cert parsing + Ed25519 signature verification (the `verify` itself is FFI). The `@peculiar/x509` import is platform-only; the Thales-side code consumes already-extracted DER bytes.                                                                    |
| `consensus-signature.ts` | 690 | Already split into "verification logic" + "crypto FFI"; the logic side is convertible.                                                                                                                                                                  |

**Subtotal: ~3.5k LOC of pure-or-nearly-pure code in the `tor` package.**

#### Refactor into pure core + adapter (SPLIT)

| File                     | LOC   | Pure-core extraction                                                                                                                                                                                                                                                                                                    |
| ------------------------ | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `util.ts`                | 173   | `BytesReader` becomes `type Cursor = { bytes; offset }` + functions. `bufferFromUint` becomes pure (returns `ReadonlyArray<number>`). `shuffleInPlace` → `shuffle(arr, entropy)` taking pre-drawn random bytes. `Mutex`, `PromiseLatch` stay in adapter.                                                                |
| `channel.ts`             | 678   | Extract `channel-core.ts`: state record, `step(state, ChannelInput)`, frame parser, padding-timer scheduler (returns deadline rather than calling `setTimeout`), digest accumulator. Keep `channel-tls.ts` as the adapter that owns the `tls.TLSSocket` and EventEmitter.                                               |
| `circuit.ts`             | ~1474 | Extract `circuit-core.ts`: hop key state, sendme windows, relay-cell tag/digest verification, EXTEND2 / RENDEZVOUS state machine. The async / `EventEmitter` / `ReadableStream` plumbing stays in `circuit-driver.ts`. The `Sha1Hash` and `Tor1Cipher` classes become functional state.                                 |
| `consensus-manager.ts`   | 328   | Extract a pure "given current consensus + now → which actions" function. The fetch / scheduling stays out.                                                                                                                                                                                                              |
| `microdesc-manager.ts`   | 488   | Same shape: pure "store + query + freshness check" functions; the actual fetch loop is the adapter.                                                                                                                                                                                                                     |
| `directory-client.ts`    | 713   | The HTTP request _shape_ (URL + headers + signed-portion offsets) is pure data; the fetch is not. Extract the request-builder and the response-validator.                                                                                                                                                               |
| `hidden-service.ts`      | ~2337 | This is the biggest prize and the biggest job. The HSv3 client is a four-phase state machine (descriptor fetch → INTRODUCE1 → wait for RENDEZVOUS2 → handshake), every phase of which is pure given inputs. Split into `hs-client-core.ts` (state machine + crypto) and `hs-client-driver.ts` (circuit + timer wiring). |
| `hidden-service-host.ts` | ~1885 | Same. ESTABLISH_INTRO, descriptor build/sign, INTRODUCE2 decrypt, hs-ntor server, rendezvous virtual hop are all pure. The IPT lifecycle / publish loop / rendezvous circuit dispatch is the adapter.                                                                                                                   |

#### Stays out of Thales (SHELL)

`tls.ts`, `tcp.ts`, `socks.ts`, `client.ts`, `node.ts`, `cli.ts`, `http-fetch.ts`,
all of `build-circuit/*` (orchestration over the above), `guard-nodes.ts`
(reads disk).

### 4.3 `packages/snowflake` (~1.9k LOC)

Snowflake is a pipeline of codecs (good) over async transports (bad). The
codecs are all small and almost-pure today.

| File                                                                          | LOC | Verdict                                                                                                                                                                                         |
| ----------------------------------------------------------------------------- | --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `encapsulation.ts`                                                            | 215 | **PURE** — `encodeEncapsulatedData`, `dataPrefixForLength` already pure. `EncapsulationDecoder` class becomes `type DecoderState = { buf; off }` + `feed(state, chunk) -> { state, frames[] }`. |
| `kcp/segment.ts`                                                              | 78  | **PURE** — codec; one `for` loop and one `out.push` rewrite to recursion.                                                                                                                       |
| `kcp/byte-queue.ts`                                                           | 55  | SPLIT — the data-structure half (`push`/`readExactly`) is pure; `waitForAtLeast` is async and stays in adapter.                                                                                 |
| `kcp/session.ts`                                                              | 371 | SPLIT — KCP ARQ is a textbook step-machine: `step(state, KcpInput) -> { state, packetsToSend[], dataReady[], retransmitDeadline? }`. Retransmit timers and UDP socket live in the adapter.      |
| `smux/protocol.ts`                                                            | 68  | **PURE** — frame codec.                                                                                                                                                                         |
| `smux/session.ts`                                                             | 438 | SPLIT — same shape as KCP: pure multiplexing state machine + Promise-based adapter.                                                                                                             |
| `smux/duplex.ts`                                                              | 90  | SHELL — extends `Duplex`.                                                                                                                                                                       |
| `ws-downlink.ts`, `tor-channel.ts`, `tor-chutney.ts`, `snowflake-ws-stack.ts` |     | SHELL — WebSocket / fetch / EventEmitter glue.                                                                                                                                                  |

**Yield:** ~1k LOC of codec + state-machine cores convertible.

### 4.4 `packages/browser` (~2.4k LOC)

Almost entirely platform glue: WebSocket shims, TLS shims wrapping
`@reclaimprotocol/tls`, `localStorage` caches, `fetch`-based HTTP.

| File                                                                            | Verdict                                                                                     |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `microdesc-cache.ts`, `consensus-cache.ts`                                      | SPLIT — the freshness-check + serialization half is pure; the `localStorage` half is shell. |
| `shims/*`, `client.ts`, `bootstrap.ts`, `http-fetch.ts`, `snowflake-channel.ts` | SHELL.                                                                                      |

**Yield:** small (~200 LOC). Not worth optimizing for.

## 5. Summary of seams

After the refactor, the rough line-count breakdown becomes:

| Category                                     | LOC   | What it is                                                                               |
| -------------------------------------------- | ----- | ---------------------------------------------------------------------------------------- |
| Thales-eligible (PURE + extracted cores)     | ~6–8k | Codecs, parsers, validators, key-derivation, protocol step-functions                     |
| Thales-eligible declared FFI (Lean `extern`) | ~50   | Crypto primitives (`sha256`, `x25519`, `ed25519Verify`, etc.), `Date.now`, `randomBytes` |
| TS-only adapter shell                        | ~14k  | Sockets, timers, EventEmitter wiring, async drivers, orchestration                       |

So **roughly a third of the codebase** can plausibly land inside Thales,
concentrated where the security-critical correctness lives: cell parsing,
ntor handshake, hs-ntor key derivation, descriptor signing, consensus
signature verification, KCP/SMUX framing, exit-policy matching.

## 6. Hard cases

These are the parts where the seam is not obvious and we should prototype
before committing.

### 6.1 Streaming hashes (`Sha1Hash`, `Sha3_256Hash`)

Tor relay-cell digest computation accumulates bytes incrementally and
_forks_ the hash mid-stream (`copy()`) to produce a digest while continuing
to feed bytes. Today this is implemented as a class that stores all chunks
and re-hashes on `digest()`.

Functional shape:

```ts
type ShaState = { acc: ReadonlyArray<number> };
function update(s: ShaState, data: ReadonlyArray<number>): ShaState;
function digest(s: ShaState): ReadonlyArray<number>; // calls FFI sha
```

This is fine. The `copy()` operation is free in the immutable model — pass
the same state value twice. **Easy.**

### 6.2 Cipher state (`Tor1Cipher`, AES-CTR)

Each hop has an AES-CTR forward/backward cipher whose counter advances with
each cell. Today this is a class with a mutable counter. Functional shape
returns `{ state, ciphertext }` from each `apply()` call. The actual block
encryption stays FFI.

The headache: AES-CTR via WebCrypto is **async** because `crypto.subtle.encrypt`
returns a Promise. For Thales, declare a synchronous `aesCtrApply` FFI that
the Lean side treats as opaque, and have the adapter's WebCrypto path
`await` and feed result bytes back into the next `step` call as a message.

### 6.3 Buffered streams with backpressure (CircuitStream, SmuxStream)

These are user-visible Duplex-shaped APIs. Backpressure is inherently about
"when should I resolve this Promise?" — not modellable inside Thales.
Strategy: keep the Duplex API in the adapter; pure core only sees discrete
"data arrived from peer" / "user wants to send N bytes" messages and
returns "produce output" / "signal high-water mark" decisions.

### 6.4 Recursion vs `for-of` over arrays

TH0010 forbids `for`/`while`. Many of the parsers use `for-of` over
`parts.split(',')` or similar. The canonical Thales replacement is `.map`

- `.filter` + `.reduce`. For multi-output parsing (split into `accepted`
  _and_ rejected halves) we either fold over a single accumulator
  `{ accepted: T[], rejected: U[] }` or split into two passes. Both work.

For genuine variable-length descents (cell parsing where each step decides
how much to consume next), structural recursion on the byte cursor with
`@decreasing remaining.length` is the right primitive.

### 6.5 Map/Set

A handful of files use `Map`/`Set` as collection types (e.g., consensus
relay lookup by fingerprint). Thales does not list `Map<K,V>` in stdlib.
Replace with sorted `ReadonlyArray<[K, V]>` and binary-search helpers, or
declare `Map`/`Set` as an extern Lean type. Sorted-array is the cleaner
choice for verification — it's structurally simple in Lean.

### 6.6 `assert` from `node:assert`

Many files use `assert(cond, msg)`. Thales has no `assert`. Replace with
`if (!cond) throw new Error(msg)` and add `@throws Error` to the
declaring function. This is mechanical but ripples through call chains
because of TH0064 (callers must catch or re-declare).

## 7. Phased roadmap

Conversion is breadth-first by ease-of-yield, not by package. Each phase
should land independently and not block the others.

### Phase 0 — foundations (no Thales code yet)

1. Pick the `Bytes` type (recommend `ReadonlyArray<number>`) and add
   `bytes.ts` adapter helpers in each package: `bufferToBytes`,
   `bytesToBuffer`, `bytesToView`.
2. Decide the FFI surface for `tor-crypto`: a small `crypto-extern.ts`
   that re-exports the primitives we'll declare as Lean `extern`.
3. Add a `thales/` subdirectory convention per package (e.g.
   `packages/tor/src/thales/`) so it is unambiguous which files are inside
   the subset and which are not. Tooling (lint, build) can target that path.
4. Add a `tsconfig.thales.json` per package that points at `src/thales/`
   and sets the strictest flags (no implicit any, exact optional, etc.) so
   we catch subset violations early before Thales itself runs.

### Phase 1 — the easy wins

Convert files that are already pure or trivially pure. Order by smallest
external footprint first so we learn the toolchain on small files:

1. `packages/tor/src/profiles.ts`
2. `packages/tor/src/fallback-dirs.ts`
3. `packages/tor/src/time.ts`
4. `packages/tor/src/exit-policy.ts`
5. `packages/snowflake/src/kcp/segment.ts`
6. `packages/snowflake/src/smux/protocol.ts`
7. `packages/crypto/src/hs-crypto.ts`
8. `packages/snowflake/src/encapsulation.ts` (split decoder class to functions)
9. `packages/tor/src/relay-cell.ts`
10. `packages/tor/src/http-parse.ts`

After phase 1: ~2k LOC of verified codecs, no behaviour changes elsewhere.

### Phase 2 — the medium wins (the BIG codecs)

11. `packages/tor/src/messaging.ts` — biggest single PURE-eligible file. Land
    the `Bytes`-based parser and switch the adapters over.
12. `packages/tor/src/util.ts` — `BytesReader` → cursor; ripple to callers.
13. `packages/tor/src/ntor.ts`
14. `packages/tor/src/cert.ts`
15. `packages/tor/src/consensus-signature.ts`

After phase 2: the entire Tor wire format and authoritative-document
verification path is verified.

### Phase 3 — the state-machine extractions

This is where the work gets real. Each item below is "extract pure core,
leave behaviour identical via the adapter":

16. `channel.ts` → `channel-core.ts` + `channel-tls.ts`
17. `circuit.ts` → `circuit-core.ts` + `circuit-driver.ts`
18. `snowflake/kcp/session.ts` → `kcp-core.ts` + `kcp-driver.ts`
19. `snowflake/smux/session.ts`→ `smux-core.ts` + `smux-driver.ts`
20. `consensus-manager.ts` → core + adapter
21. `microdesc-manager.ts` → core + adapter
22. `directory-client.ts` → request-builder/validator + fetch driver

Each is a multi-PR refactor; do them one at a time so the existing test
suite catches regressions on each split.

### Phase 4 — the hidden-service stack

23. `hidden-service.ts` → `hs-client-core.ts` + driver
24. `hidden-service-host.ts` → `hs-host-core.ts` + driver

These are the largest files and the most security-critical; they go last
because by this point the Phase-1 codecs they depend on are already
verified, which de-risks the cores.

### Phase 5 — opportunistic tightening

- Add `@total` annotations once each module passes Thales termination
  checking. Most encoders should be totalizable; the parsers will need
  `@throws Error` rather than `@total` because malformed input is a
  legitimate failure mode.
- Consider whether any of the `SHELL` adapters can be shrunk further
  (e.g., `socks.ts` has a parser sub-module that's secretly pure).

## 8. What stays out, and why we should accept that

The following are **not** worth trying to coerce into Thales:

- **TLS handshakes** (Node's `node:tls`, `@reclaimprotocol/tls`). These are
  themselves complex stateful protocols and we are not re-implementing them.
  They sit at the bottom of our stack as opaque byte channels.
- **Socket I/O** (`net.Socket`, `WebSocket`, `fetch`). Effects.
- **Timer-driven liveness** (netflow padding, KCP retransmit, circuit-build
  timeouts, IPT rotation). The _decision_ of when to fire is pure
  (`step` returns `armTimer { deadlineMs }`); the _firing_ is shell.
- **The `EventEmitter`-shaped public API.** The user-facing `Circuit`,
  `CircuitStream`, `SocksProxyServer`, `HiddenServiceHost`, `TorClient`
  classes are part of the package's contract. We keep them; they delegate
  to a Thales-verified core.
- **Tests** (`*.spec.ts`, `*.test.ts`). Vitest depends on async/Promise.
  We can have _additional_ Thales-side conformance tests, but the existing
  suite stays as-is.

## 9. Open questions to resolve before Phase 1

1. Does Thales accept `for-of` over arrays, or only `.map`/`.reduce`/
   recursion? The doc says "no `for`" — we should verify on a small
   example before committing.
2. Does `as const` on a record literal (used heavily for cell-type tables
   in `relay-cell.ts` / `messaging.ts`) compile? If not, those tables
   need to be inlined into `switch`.
3. How does Thales handle generic helpers like `BytesReader<T>` returning
   `[T, Cursor]` tuples? Tuples are listed as allowed; confirm with a
   small parser prototype.
4. What's the FFI story — does Thales support `declare` for
   externally-implemented functions, or do we need a Lean-side companion
   file written by hand? This shapes whether `tor-crypto` primitives are
   reachable from verified code at all.
5. How aggressively should we adopt `@total`? Defaulting to `partial def`
   (no `@total`) for everything still gives us the type-level guarantees;
   `@total` adds termination but forbids `@throws`. Probably: `@total` on
   encoders and pure data transforms; plain (partial) on decoders that
   can fail on malformed input.

Answering these on a one-file proof-of-concept (recommend `exit-policy.ts`
— smallest, simplest, has all the patterns) before Phase 1 starts will
save a lot of churn.
