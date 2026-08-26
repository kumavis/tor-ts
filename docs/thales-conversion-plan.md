# Thales conversion plan

A roadmap for moving as much of `tor-ts` as possible into the
[Thales TypeScript subset](https://github.com/jessealama/thales/blob/main/docs/subset.md)
so it can be transpiled to Lean 4 and machine-checked.

**Revised for Thales 0.7.** The first version of this plan was written
against Thales 0.5, whose subset banned loops, mutation, classes,
arrays, and modules outright. 0.7 lifted all five to varying degrees,
which changes what is reachable. See
[`packages/core/docs/MIGRATION.md`](../packages/core/docs/MIGRATION.md)
for the measurements behind the revision.

The goal is not 100% coverage. Tor is a network stack of sockets,
timers, and events; `async`/`await` is out of the subset and always will
be. The goal is to draw module-level seams so that wire-format codecs,
protocol state machines, key-derivation math, and policy evaluation live
inside Thales, with a thin imperative shell driving I/O.

---

## Status

`packages/core` currently holds **20 verified modules / 361 theorems**,
covering:

| area                      | modules                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| Wire vocabulary           | `messageCellType`, `relayCommand`, `relayEndReason`, `destroyReason`, `certType`, `wireTypes`, `smuxCmd` |
| Byte primitives + parsers | `bytes`, `cellHeader`, `kcpHeader`, `encapsulationPrefix`                                                |
| Protocol state machines   | `channelState`, `circuitState`, `streamState`, `hsClientState`, `hsHostState`                            |
| Policy / arithmetic       | `exitPolicy`, `seq32`, `sendmeWindow`, `versionNegotiation`                                              |

Every numeric code that flows through a circuit's lifecycle has a
verified DU representation with a kernel-checked round-trip, and all
five protocol layers (channel → circuit → stream → HS client → HS host)
have a verified `step` function with terminal-state and
protocol-error theorems.

---

## 1. What Thales still rules out

Rules that bite this codebase, as of 0.7:

| Code          | Rule                                                               | Impact                                                                       |
| ------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| TH0012        | No `async`/`await`/`Promise`                                       | **Structural.** 543 hits in non-test code. This is what the seam exists for. |
| TH0087        | String methods limited to `length`/`startsWith`/`endsWith`/`split` | Blocks every text parser (consensus, microdesc, HTTP, exit-policy parsing)   |
| —             | No crypto FFI                                                      | Blocks anything calling SHA-3/SHAKE/Curve25519/Ed25519 from verified code    |
| —             | Exported DUs can't be matched                                      | Blocks cross-module composition of our core types (MIGRATION F3)             |
| TH0010        | Module-level loops; loops in class members                         | Minor — our style is function-local anyway                                   |
| TH0004/TH0002 | Mutating array methods; element assignment                         | Pushes buffer code toward `slice`/`concat`                                   |
| TH0092        | No `typeof`/`void`/`delete`                                        | Minor — DUs replace `typeof` narrowing                                       |

Effects Thales has no answer for, which must sit **outside** the seam:

- Timers (`setTimeout`, `setInterval`), wall-clock (`Date.now()`)
- RNG (`crypto.randomBytes`, `getRandomValues`)
- Sockets (`tls.connect`, `net.Socket`, `WebSocket`, `fetch`)
- Mutable byte buffers (`Buffer.alloc`, `writeUIntBE`, `DataView.setUint32`)
- `EventEmitter` dispatch

### Newly _available_ since 0.5

These lifted bans are what makes the revision worth doing:

- **Loops** — `for-of`, canonical `for (let i = 0; i < B; i++)` (which
  is `@total`-friendly), `while`/`do-while` (not `@total`)
- **Function-local mutation** — `let` reassignment lowering to
  `Id.run do` + `let mut`
- **Arrays** — `map`/`filter`/`reduce`/`concat`/`slice`/`length` plus a
  conditionally-lowered second tier
- **Immutable classes** — `structure` + receiver-first namespace
- **ES modules** — named `import`/`export` (with the F3 caveat)
- **Refinement types** — `Integer`/`Natural`/`Byte`/`Bit`, compile-time
  range enforcement

---

## 2. The seam pattern

Unchanged by 0.7, because `async` is still out. Every stateful subsystem
splits three ways:

```
┌──────────────────────────────────┐
│  Effect adapter (TS-only)        │  sockets, timers, EventEmitter,
│                                  │  Promises, RNG, wall-clock
├──────────────────────────────────┤
│  Wiring shim (TS-only, tiny)     │  turns events into Msg values,
│                                  │  calls step(), dispatches Outs
├──────────────────────────────────┤
│  Pure core (Thales-verified)     │  type State, type Input;
│                                  │  step(state, input) -> State
│                                  │  encoders, decoders, validators
└──────────────────────────────────┘
```

The five state machines already in core validate the pattern. Their
`step` functions deliberately take _parser-extracted signals_
(`recv_versions { serverVersion }`, `recv_destroy { reason }`) rather
than raw bytes, which is what let them land before the byte layer was
complete — the shell parses, the core decides.

Effects become inputs: the shell calls `Date.now()` / `randomBytes(n)`
and packages the result into the `Input` DU. That turns impurity into a
data dependency, which Thales handles fine.

---

## 3. Cross-cutting decisions

### 3.1 The `Bytes` representation — revisit

Core currently models byte buffers as a cons-cell DU:

```ts
type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };
```

That choice was forced at 0.5, where arrays had no usable stdlib. At
0.7, `Byte[]` is a live option, with real trade-offs:

|                                 | cons-cell `ByteList`        | `Byte[]`                                   |
| ------------------------------- | --------------------------- | ------------------------------------------ |
| Seam marshalling                | needs list↔array conversion | direct                                     |
| Structural recursion / `@total` | natural                     | needs canonical `for` or `slice` recursion |
| Existing proofs                 | 60+ theorems assume it      | all would need rewriting                   |
| Element range                   | comment-level convention    | enforced by `Byte`                         |
| Cross-module sharing            | blocked by F3               | `Byte[]` is not a DU — **not blocked**     |

The last row is the interesting one: an array-of-`Byte` representation
sidesteps F3 entirely, because there is no DU to export. That may make
it the right answer even before F3 lands upstream.

**Recommendation:** prototype `Byte[]` on one module (`kcpHeader` is the
smallest byte-consumer) and compare proof ergonomics before committing.
Do not migrate the whole byte layer speculatively.

### 3.2 Numbers

`bigint` → Lean `Int`; `number` → Lean `Float`. Wire integers stay
`bigint` for bit-exactness. **Caveat:** the refinement types
(`Byte`/`Natural`) are `Float` subtypes and do not compose with
`bigint` — adopting `Byte` for byte values means moving them off
`bigint`. That tension is the main thing to settle in the 3.1
prototype.

Also note `%` on `bigint` is currently broken (MIGRATION F2); core uses
a `truncMod` helper instead.

### 3.3 Effects as inputs

Unchanged: the shell supplies `nowMs`, entropy, and parsed cell fields
as `Input` constructors. See any of the five state machines.

---

## 4. Per-package landscape

Verdicts revised against the 0.7 subset. **PURE** = convertible as-is;
**SPLIT** = pure core extractable behind an adapter; **SHELL** =
inherently effectful.

### 4.1 `packages/tor` (~17.5k LOC)

**Already in core:** the wire vocabulary from `messaging.ts`,
`relay-cell.ts`, `cert.ts`, `circuit.ts`; the evaluation half of
`exit-policy.ts`; the lifecycle logic of `channel.ts`, `circuit.ts`,
and `hidden-service{,-host}.ts`.

**Newly reachable at 0.7:**

| target                                                             | why it moved                                                          | blocker                                                          |
| ------------------------------------------------------------------ | --------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Cell **encoders** (`serializeCellWithPayload`, `serializeExtend2`) | canonical `for` is `@total`-friendly, so length-driven emission works | none — do this next                                              |
| `exit-policy.ts` **parsing** half                                  | `string.split` covers `parsePortList`                                 | needs `parseInt` substitute; `split` + digit folding may suffice |
| Full `parseCellHeader` composition                                 | —                                                                     | **F3** (needs shared `ByteList`), or switch to `Byte[]` per 3.1  |
| `http-parse.ts`                                                    | `split` + `startsWith` cover most of it                               | no `indexOf`/`trim` (TH0087) — partial only                      |

**Still SHELL:** `tls.ts`, `tcp.ts`, `socks.ts`, `client.ts`, `node.ts`,
`cli.ts`, `http-fetch.ts`, `directory-client.ts` (fetch),
`build-circuit/*` (orchestration), `guard-nodes.ts` (disk).

**Still blocked on crypto FFI:** `ntor.ts`, `consensus-signature.ts`
verification, hs-ntor key derivation. These are _pure_ but call
primitives Thales cannot see. Unblocking needs Lean-side `extern`
declarations — worth raising upstream as a feature request, since it
gates the most security-critical code in the repo.

### 4.2 `packages/crypto` (~860 LOC)

Unchanged verdict. `hashes.ts` and `curves.ts` bottom out in platform
crypto (FFI-blocked). `hs-crypto.ts`'s bigint/byte math (`mac`, `dMac`,
`u64be`, LE codecs) is pure and convertible — `bigIntToBytesLE` in
particular is now writable with a canonical `for`, where at 0.5 it was
blocked by the `@decreasing`/`Nonempty` gap.

`aes.ts` stays SHELL (WebCrypto, async).

### 4.3 `packages/snowflake` (~1.9k LOC)

**Already in core:** `smuxCmd`, the KCP LE-decode primitives, the
encapsulation length-prefix decoder.

**Newly reachable:** the full KCP segment decoder and SMUX header
decoder — both are chained field-decodes that were impractical at 0.5
purely because of per-module redeclaration overhead. Same F3 / `Byte[]`
decision applies.

The KCP ARQ state machine (`kcp/session.ts`) is the biggest remaining
SPLIT candidate in the repo and a natural fit for the `step` pattern:
`step(state, KcpInput) -> { state, packetsToSend, dataReady, retransmitDeadline }`.
Retransmit timers stay in the adapter.

### 4.4 `packages/browser` (~2.4k LOC)

Unchanged: almost entirely platform glue. The freshness-check halves of
`microdesc-cache.ts` / `consensus-cache.ts` are the only SPLIT
candidates, and they're small.

### 4.5 New since this plan was written: HS proof-of-work

`origin/main` added an Equi-X proof-of-work client (proposal 327) in
`packages/crypto` + `packages/tor`. PoW is a strong core candidate —
pure, deterministic, arithmetic-heavy, with checkable invariants
(effort/difficulty relationships, solution verification). Assess after
rebasing onto main.

---

## 5. Roadmap

Ordered by value per unit of effort.

**Now (unblocked, small):**

1. Land the 0.7 migration — see
   [`MIGRATION.md`](../packages/core/docs/MIGRATION.md) Stage 1.
2. File the two new upstream bugs (F2 `%`-on-bigint, F3 exported DUs).
3. Cell **encoders**, using the canonical `for` shape. Pairs each
   existing decoder with its inverse and unlocks round-trip theorems of
   the form `parse (serialize c) = some c` — the strongest property this
   codebase can state about its wire format.

**Next (needs a decision):**

4. Prototype `Byte[]` vs cons-cell `ByteList` on `kcpHeader` (§3.1). The
   outcome determines whether the full cell parser waits on F3.
5. Full `parseCellHeader` / KCP segment / SMUX header composition, once
   4 is settled.

**Later (needs upstream):**

6. Crypto FFI — raise upstream; gates `ntor`, consensus-signature
   verification, hs-ntor.
7. Text parsers — gated on the string surface widening past
   `split`/`startsWith`/`endsWith`.

**Ongoing:**

8. Rebase onto `tor-ts` main; assess the Equi-X PoW client as a core
   candidate.

---

## 6. What stays out, permanently

- **TLS** (`node:tls`, `@reclaimprotocol/tls`) — complex stateful
  protocols we are not re-implementing; they sit below us as opaque byte
  channels.
- **Socket I/O** — effects.
- **Timer firing** — the _decision_ of when to fire is pure (`step`
  returns a deadline); the firing is shell.
- **The `EventEmitter`-shaped public API** — `Circuit`, `CircuitStream`,
  `SocksProxyServer`, `HiddenServiceHost`, `TorClient` are the package's
  contract. They keep their shape and delegate inward.
- **The vitest suites** — they depend on async. Lean proofs are
  complementary to them, not a replacement: the tests check behaviour
  under real conditions, the theorems check what `step` is mathematically
  guaranteed to do.
