# `tor-core`

The verified pure core of `tor-ts`.

Every TypeScript file under `src/` is written in the
[Thales TypeScript subset](https://github.com/jessealama/thales/blob/main/docs/subset.md)
so it can be transpiled to Lean 4 and kernel-checked. Specification
theorems live under `Spec/` and are checked by `lake build` in CI. If a
file in this package fails either step, the build fails.

The seam strategy and per-package conversion plan live in
[`docs/thales-conversion-plan.md`](../../docs/thales-conversion-plan.md).
The conventions and recipes for adding a new module are in
[`docs/PATTERNS.md`](docs/PATTERNS.md). Filed Thales 0.5 quirks are
in [`docs/thales-issues.md`](docs/thales-issues.md).

## Layout

```
packages/core/
├── src/                     TypeScript source (Thales subset, runs as JS)
│   ├── bytes.ts
│   ├── cellHeader.ts
│   ├── certType.ts
│   ├── channelState.ts
│   ├── circuitState.ts
│   ├── destroyReason.ts
│   ├── exitPolicy.ts
│   ├── messageCellType.ts
│   ├── relayCommand.ts
│   ├── relayEndReason.ts
│   ├── sendmeWindow.ts
│   ├── seq32.ts
│   ├── streamState.ts
│   └── wireTypes.ts
├── Generated/               Thales-emitted Lean sidecars (gitignored)
├── Spec/                    Hand-written Lean theorems
│   ├── Bytes.lean
│   ├── CellHeader.lean
│   ├── CertType.lean
│   ├── ChannelState.lean
│   ├── CircuitState.lean
│   ├── DestroyReason.lean
│   ├── ExitPolicy.lean
│   ├── MessageCellType.lean
│   ├── RelayCommand.lean
│   ├── RelayEndReason.lean
│   ├── SendmeWindow.lean
│   ├── Seq32.lean
│   ├── StreamState.lean
│   └── WireTypes.lean
├── docs/thales-issues.md    Bug drafts for jessealama/thales
├── lakefile.lean            Lean project; `require`s Thales
├── lean-toolchain           Pinned Lean version
├── tsconfig.json            Strict TS settings
└── scripts/verify.sh        Build Thales → emit sidecars → `lake build`
```

## Running locally

You need [`elan`](https://github.com/leanprover/elan) on `$PATH`. Then:

```bash
yarn workspace tor-core verify
```

The first run clones and builds Thales into `packages/core/.thales/`,
which takes a few minutes (~57 build steps); subsequent runs reuse the
binary as long as `THALES_REV` is unchanged.

## What's inside

| Module               | Functions                                                                                                                                                                               | Theorems in `Spec/` |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `exitPolicy.ts`      | `portInRange`, `anyRangeContainsPort`, `policyAllowsPort`, `policyAllowsAllPorts`, `policyAllowsAnyPort`, `isPortRangeListEmpty`, `isFullPortRange`, `policyRejectsAll`                 | 25                  |
| `seq32.ts`           | `uint32`, `add32`, `sub32`, `asInt32`, `itimediff`, `seqLt`, `seqLe`                                                                                                                    | 15                  |
| `relayEndReason.ts`  | `relayEndReasonCode`, `relayEndReasonFromCode`, `getStreamRetryBehavior`, `isRetryableEndReason`                                                                                        | 12                  |
| `messageCellType.ts` | `messageCellTypeCode`, `messageCellTypeFromCode`, `isVariableLengthCell`                                                                                                                | 16                  |
| `relayCommand.ts`    | `relayCommandCode`, `relayCommandFromCode`, `isHiddenServiceCommand`, `isPaddingCommand`, `isFlowControlCommand`                                                                        | 18                  |
| `bytes.ts`           | `byteListLength`, `byteListConcat`, `consIntoSplit`, `trySplit`, `bigEndianUintAux`, `bigEndianUint`, `bytesToBigIntLE`                                                                 | 20                  |
| `cellHeader.ts`      | `circIdLengthForVersion`, `parseCircId`, `parseCommand`, `parseLengthPrefix`, `parsePayload`, `parseFixedPayload` (and locally-redeclared bytes primitives, until Thales adds `import`) | 25                  |
| `wireTypes.ts`       | `addressTypeCode`/`FromCode`, `linkSpecifierTypeCode`/`FromCode`, `handshakeTypeCode`/`FromCode`, `relayResolvedTypeCode`/`FromCode`, `isResolvedError`                                 | 24                  |
| `destroyReason.ts`   | `destroyReasonCode`, `destroyReasonFromCode`, `isCleanDestroy`                                                                                                                          | 10                  |
| `certType.ts`        | `certTypeCode`, `certTypeFromCode`, `isLegacyX509Cert`, `isHiddenServiceCert`                                                                                                           | 8                   |
| `channelState.ts`    | `step` + per-state helpers, `isHandshaking`, `isOpen`, `isClosed`, `linkVersionOf`                                                                                                      | 23                  |
| `circuitState.ts`    | `step` + per-state helpers, `advanceBuilding`, `isBuilding`, `isOpen`, `isDestroyed`, `hopCount`                                                                                        | 16                  |
| `streamState.ts`     | `step` + per-state helpers, `isInit`, `isAwaiting`, `isOpen`, `isClosed`                                                                                                                | 18                  |
| `sendmeWindow.ts`    | `decrementWindow`, `applySendme`, `isWindowDepleted`, `shouldEmitSendme`, `isValidWindow`, `canSendData`, `wouldDeplete`                                                                | 23                  |

The intent is to port modules into here incrementally per the conversion
plan, **rejecting any addition that isn't fully Thales-eligible and
proven**.

## Known limitations & quirks

These were discovered during the first end-to-end run; capturing them so
later modules don't re-learn the same things.

- **No `export` keyword.** Thales 0.5's parser rejects
  `export function …` / `export type …` / trailing `export {}`. The
  subset doc lists `import`/`export` as supported, but the implementation
  doesn't agree yet. Until that lands upstream, files in `src/` are
  module-local — they can be verified, but they aren't importable from
  the rest of the workspace. This is fine for now (the goal is to grow
  the verified surface; integration with the impure shell comes later).
- **Lean reserved field names.** Thales emits TypeScript field names
  verbatim into Lean structs. Lean treats `end` as a keyword, so a TS
  field named `end` produces uncompilable Lean. Any verified module that
  needs a field called `end`, `match`, `mut`, `do`, etc. must rename it
  on the TS side.
- **`type X = { … }` collapses to `Unit`.** Thales 0.5 only emits
  full struct definitions for `interface` declarations, not record-shaped
  type aliases. Use `interface` for verified records.
- **`bigint` not `number`.** Thales maps `number` to Lean `Float` and
  `bigint` to Lean `Int`. Anything that wants integer reasoning (port
  numbers, byte values, sequence numbers, lengths) should be `bigint`.
  The TS-side adapter does `BigInt(x)` at the seam.
- **No `import` between Thales files.** The Thales 0.5 parser rejects
  `import` statements in user files just like it rejects `export`. Each
  verified module must be self-contained. Cross-module composition waits
  for an upstream Thales fix.
- **No array methods yet.** Despite the subset doc listing `.map`,
  `.filter`, `.reduce`, etc., the Thales 0.5 prelude only exposes
  `Option<T>` / `Result<T, E>`. Iteration over a sequence is done via a
  discriminated-union cons-cell list (`{ kind: 'nil' } | { kind: 'cons';
head; tail }`) and structural recursion with `switch (xs.kind)`. The
  TS-side seam adapter converts arrays at the boundary. This is the
  pattern `total-recursion.ts` uses in the upstream Thales examples and
  is what compiles cleanly to `inductive` types in Lean.
- **Object literals don't compile for `interface` types.** Constructing
  a value of an `interface`-typed (or single-record `type`-aliased)
  record with `{ … }` emits the literal text `(unsupported expr)` —
  silently broken. DU constructors via the `kind` discriminator
  (`{ kind: 'cons', head, tail }`) work fine. The practical
  consequence: `interface` types can be **consumed** in verified code
  but not **constructed** there. Builders that produce records have to
  live in the impure shell. See
  [`docs/thales-issues.md`](docs/thales-issues.md) for a filed repro.
- **Switch narrowing doesn't reach into nested switches.** A
  `switch (policy.kind) { case 'reject': switch (policy.ports.kind)
{ case 'cons': policy.ports.head ... } }` fails type-check inside
  Thales (`Property 'head' does not exist on type 'object | object'`).
  Workaround: hoist the inner switch into a small helper function that
  takes the narrowed sub-record as an argument.
- **`split_ifs`, `linarith`, `ring`, `interval_cases` are Mathlib tactics** —
  they aren't available in `Spec/` (we only have core Lean + batteries via
  Thales's own dependency). Use `by_cases h : <cond>` + `if_pos h` /
  `if_neg h` for splitting on `if`, and `omega` for arithmetic
  obligations over `Int`/`Nat`. `omega` is surprisingly strong: given
  `h : f x = a + b`, it'll close `f x = c` if `a + b = c` is decidable.
  For finite-range case-splits over `Int`, derive the disjunction with
  `omega` (`have : c = 1 ∨ c = 2 ∨ ... := by omega`) and `rcases`.
- **Switching on `f(x).kind` silently emits `()`.** Thales 0.5 only
  recognizes `switch (param.kind)` as a DU dispatch — switching on a
  function call result or a `const`-bound DU silently emits `()` as
  the body, which Lean then rejects. Workaround: always switch on a
  direct parameter; if you want to delegate to another function's
  result, inline the policy and prove agreement in Spec instead. See
  Issue 6 in `docs/thales-issues.md`.
- **`deriving Repr` only.** Thales emits inductives with only `Repr`,
  not `DecidableEq`. Lean's `decide` and `simp` need decidable
  equality for `r = .someConstructor` to work; add
  `deriving instance DecidableEq for MyType` in the corresponding
  `Spec/*.lean` file.
