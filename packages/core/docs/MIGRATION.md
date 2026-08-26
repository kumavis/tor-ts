# Thales 0.5 → 0.7 migration

Status of `tor-core` against upstream Thales `3c71913` (0.7-forthcoming,
Lean 4.33.0), and the plan for getting there.

Everything in the "Findings" section was measured, not read off the
docs — the probe procedure is at the bottom so it can be re-run.

---

## TL;DR

|                                                          |                               |
| -------------------------------------------------------- | ----------------------------- |
| Modules that still **emit**                              | **20 / 20**                   |
| Modules that fully **build** (emit + all `Spec/` proofs) | **18 / 20**                   |
| Proof changes needed for Lean 4.29 → 4.33                | **zero**                      |
| Blocking regressions                                     | **1** (`%` on `bigint`)       |
| Headline win (deduplicate `ByteList` via imports)        | **blocked** — see F3          |
| Byte representation                                      | **stays `ByteList`** — see F5 |

The migration is cheap. The _payoff_ is smaller than the upstream
changelog suggests, because the one feature we most wanted — sharing a
discriminated-union type across modules — does not work for types we
pattern-match on.

Post-migration the package sits at **21 modules / 411 theorems**: the
0.7 subset did unlock one substantial addition, `byteEncode.ts`, which
brought core its first round-trip theorems (see "Harvest", Stage 3.3).

---

## What changed upstream

189 commits, 2026-04-30 → 2026-08-16. Version 0.5 → 0.7-forthcoming.
Lean 4.29.0 → 4.33.0. Diagnostic codes ~25 → 63.

Four of our six filed issues are **closed**:

| ours | upstream                                              | subject                                | state      |
| ---- | ----------------------------------------------------- | -------------------------------------- | ---------- |
| 1    | [#11](https://github.com/jessealama/thales/issues/11) | Lean reserved keywords as field names  | **closed** |
| 2    | [#13](https://github.com/jessealama/thales/issues/13) | single-record `type` alias → `Unit`    | **closed** |
| 3    | [#15](https://github.com/jessealama/thales/issues/15) | object literals → `(unsupported expr)` | open       |
| 4    | [#16](https://github.com/jessealama/thales/issues/16) | array stdlib not callable              | open       |
| 5    | [#18](https://github.com/jessealama/thales/issues/18) | `import`/`export` rejected             | **closed** |
| 6    | [#19](https://github.com/jessealama/thales/issues/19) | `switch` on `f(x).kind` emits `()`     | **closed** |

The subset also _widened_ well beyond bug fixes — loops, function-local
mutation, immutable classes, a real array stdlib, ES modules, and a new
refinement-type family (`Integer`/`Natural`/`Byte`/`Bit`). See
[`PATTERNS.md`](PATTERNS.md) for what that means for writing core
modules, and [`../../docs/thales-conversion-plan.md`](../../docs/thales-conversion-plan.md)
for what it means for how much of `tor-ts` is now reachable.

`async`/`await` remains out (TH0012). The seam architecture is unaffected.

---

## Findings

### F1 — All 20 modules still emit. 18 fully build. Proofs are untouched.

Running every `src/*.ts` through the 0.7 binary: **20 emit OK, 0 emit
failures.** Building the result together with the existing `Spec/*.lean`
under Lean 4.33: **18 of 20 succeed**, and **not one theorem needed
editing**. All 361 theorems survived the toolchain jump as written.

The two failures are both in `Generated/`, not in `Spec/` — an emitter
regression, not proof rot. That is the best possible shape for this
result: our proof corpus is not coupled to the Thales version.

The only other diff is two cosmetic `unusedSimpArgs` lint warnings in
`Spec/VersionNegotiation.lean` that were already there at 0.5.

### F2 — Regression: `%` on `bigint` emits uncompilable Lean

`x % m` where both operands are `bigint` now lowers to `jsMod`, which is
the **Float** (i.e. `number`) ES2023 remainder helper:

```ts
function modBig(x: bigint): bigint {
  return x % 256n;
}
```

```lean
partial def modBig (x : Int) : Int :=
  (jsMod x 256)          -- jsMod : Float → Float → Float
```

```
error: Application type mismatch: the argument `x` has type `Int`
       but is expected to have type `Float` in the application `jsMod x`
```

Only `%` is affected — `+`, `-`, `*`, `/` and every comparison lower
correctly for `bigint`. This is an accept-then-uncompilable emit hole,
the same class as the bugs we filed against 0.5.

**Affects:** `seq32.ts`, `encapsulationPrefix.ts`.

**Workaround (verified compiling):** both TS `bigint /` and Lean `Int./`
truncate toward zero, so the truncated remainder can be written without
`%`:

```ts
// x % m
x - (x / m) * m;
```

Emits `(x - ((x / m) * m))` and compiles. Semantically exact for the
non-negative operands our two modules use.

### F3 — Exported discriminated-union types cannot be pattern-matched

This is the finding that matters most, because de-duplicating `ByteList`
across `bytes.ts` / `cellHeader.ts` / `kcpHeader.ts` /
`encapsulationPrefix.ts` was the main reason to want ES modules.

Measured matrix, for a recursive DU `L` and a function that dispatches
on `L.kind`:

| form                                 | subset check | emit                                | Lean                              |
| ------------------------------------ | ------------ | ----------------------------------- | --------------------------------- |
| local type, local fn, `switch`       | ok           | **ok**                              | **ok**                            |
| local type, `export` fn, `switch`    | ok           | **ok** (type → `private inductive`) | **ok**                            |
| `export` type, local fn, `switch`    | **TH0041**   | —                                   | —                                 |
| `export` type, `export` fn, `switch` | ok           | **TH9005**                          | —                                 |
| `export` type, `if (x.kind === '…')` | ok           | ok                                  | **fails**: `Invalid field 'kind'` |
| `export` type, never destructured    | ok           | ok                                  | ok                                |
| `export interface` + field reads     | ok           | ok                                  | ok                                |

So an exported DU can be _constructed_ and _passed around_, but the
moment a module wants to branch on its discriminant, both available
forms fail — `switch` is rejected outright, and the `if`/`else`
alternative emits an `x.kind` projection that Lean has no accessor for
(inductives get constructors, not a `.kind` field).

Every DU in `tor-core` is pattern-matched. So **the import win is not
available for our core types today.** What _is_ available:

- exported **functions** (the DU stays `private inductive` in its module);
- exported **`interface`** types with field reads;
- exported DUs that are only constructed, never destructured.

### F4 — New restrictions do not bite us

0.7 adds 38 diagnostics. The ones most likely to break previously-valid
code — TH0026 (conditions and `!`/`&&`/`||` operands must be `boolean`),
TH0032 (no shadowing declarations), TH0105 (declare-before-use at top
level), TH0041 (one lowerable `switch` shape), TH0092 (no `typeof`) —
**all pass on our existing 20 modules unchanged.** The house style we
converged on at 0.5 happened to already satisfy them.

### F5 — Decision: keep `ByteList`, do not adopt `Byte[]` or `Byte`

NEXT-STEPS §3 and §4 asked whether to move byte buffers from the
hand-rolled cons-cell DU to `Byte[]`, now that arrays and refinement
types exist. **Both answers are no.** Measured against `3c71913`:

**1. There is no way to split an array.** `.slice` and `.concat` do not
exist on any array type — not `bigint[]`, not `number[]`. The array
builtin table in `Thales/TypeCheck/Builtins.lean` has arms for
`length`, `forEach`, `map`, `filter`, `reduce`, `join`, `indexOf`,
`includes`, `lastIndexOf`, `some`, `every`, `findIndex` — and nothing
else. `subset.md` claims otherwise in three places; that mismatch is
[issue 15](thales-issues.md).

This is decisive on its own. Core's parsers are built on `trySplit`:
take `n` bytes, hand back the remainder. `map`/`filter`/`reduce` cannot
express it. Without `slice`, the array representation cannot support
incremental parsing at all.

**2. `@total` does not survive array recursion.** Even given `slice`,
`subset.md` states Lean cannot prove a sliced array is smaller, so a
recursive array parser would be `partial def` — outside the kernel's
termination check, which is most of what we are buying.

**3. Loops are proof-hostile here.** The remaining iteration route is
`for-of` / canonical `for`, which lower into `Id.run do` with `let mut`.
The canonical form also shims the loop index to **`Float`**
(`let i : Float := i.toFloat`). Our 411 theorems are `Int` + `omega`;
`omega` does not apply to `Float` at all, and without Mathlib we have no
loop-invariant machinery to fall back on.

**4. `Byte` is a `Float` subtype.** `@thales/prelude` defines
`Byte = number`, mirrored in Lean as `{ x : Float // isByte x = true }`.
Adopting it would move every byte value off `Int`, which is exactly the
`omega` cliff again — its own `Inhabited` instance needs
`native_decide`. So §4 is answered by §3's evidence: **`Byte` is a
correctness upgrade on the TS side and a proof downgrade on the Lean
side**, and the Lean side is the point.

**What arrays genuinely do win**, and it is real: an exported
array-typed alias _can_ be imported and used — `.length` and computed
index access both work across a module boundary. Verified directly:

```ts
// lib.ts
export type Buf = bigint[];
export function bufLen(b: Buf): number {
  return b.length;
}

// app.ts — emits and compiles
import { bufLen, type Buf } from './lib';
export function twiceLen(b: Buf): number {
  return bufLen(b) + b.length;
}
```

So arrays sidestep F3/#14 entirely, as NEXT-STEPS §3 predicted. But the
prize for sidestepping #14 is deduplicating ~200 lines, and the price is
giving up structural recursion, `@total`, and `omega`. Not close.

**Consequence:** `ByteList` stays. The duplication stays with it until
#14 lands upstream. Indexed reads under `noUncheckedIndexedAccess` are
`T | undefined` and need bind-then-narrow, which is one more small tax
on the array route, though not one that mattered to the decision.

---

## Plan

### Stage 1 — Land the migration (small, do now)

1. Bump `lean-toolchain` to `leanprover/lean4:v4.33.0`.
2. Bump the `require thales` pin in `lakefile.lean` and the
   `THALES_REV` default in `scripts/verify.sh` to `3c71913`.
3. Work around F2 in `seq32.ts` and `encapsulationPrefix.ts`: replace
   `a % b` with `a - (a / b) * b` behind a named helper so the intent
   stays legible, and add a `Spec` theorem pinning the helper to the
   mathematical remainder so the workaround is itself verified.
4. Re-run `verify.sh`; expect 20/20 and 361 theorems.
5. Update the CI cache key (it hashes `verify.sh`, so the pin bump
   invalidates it automatically).

No proof edits. No module rewrites.

### Stage 2 — File the new bugs upstream

The first two are accept-then-uncompilable emit holes; TH9005's own
message asks for a report. Drafts go in
[`thales-issues.md`](thales-issues.md).

- **`%` on `bigint` routes through the Float `jsMod`** (F2). Minimal
  repro is four lines; the fix is presumably to select `Int.emod` (or
  Lean `%`) when both operands are `Int`.
- **Exported DU types are un-matchable** (F3). Worth filing as one
  report with the full matrix above, since the two symptoms
  (TH0041/TH9005 on `switch`, bad `.kind` projection on `if`) are the
  same underlying gap seen from two directions.
- **Array `.slice`/`.concat` are documented but absent** (F5). A doc/
  surface mismatch rather than an emit hole, but it is what decided the
  byte-representation question, and TH0002's remedy text currently
  recommends a method that does not exist.

Landing F3 upstream is the single highest-leverage thing for this
project: it unblocks module composition, which unblocks the full cell
parser, which is the next substantive verification target.

### Stage 3 — Harvest the widened subset (after Stage 1)

Independent of F3, several things are newly reachable and worth doing in
priority order:

1. ~~**`Byte` refinement type.**~~ **Rejected — see F5.** `Byte` is a
   `Float` subtype, so adopting it moves byte values off `Int` and out
   of `omega`'s reach.
2. ~~**Arrays instead of cons-cell lists.**~~ **Rejected — see F5.**
   `slice`/`concat` do not exist on arrays, so `trySplit` has no array
   equivalent, and `@total` does not survive array recursion anyway.
3. **Encoders.** ✅ **Done** — `byteEncode.ts`, 46 theorems, core's
   first round-trip results. Not via loops, though: the canonical `for`
   shape emits into `Id.run do` with a `Float`-shimmed index, which is
   proof-hostile without Mathlib. What worked instead was making the
   _width_ a unary DU, so recursion on it is structural and every
   encoder is `@total`. `Spec/ByteEncode.lean` proves
   `decode (encode v w) = v` for both endiannesses, plus the
   stream-shaped `trySplit (encode v w ++ rest) = ok (encode v w) rest`.
   See the header of `src/byteEncode.ts` for why the obvious
   `width: bigint` signature cannot work.
4. **`string.split`.** The string surface is still tiny (`length`,
   `startsWith`, `endsWith`, `split`) — but `split` alone is most of
   `parsePortList`, so the parsing half of `exit-policy.ts` is worth
   re-examining. Still open.

### Stage 4 — Rebase onto `tor-ts` main

Our branch is 7 commits behind `origin/main`, which has since added an
HS proof-of-work client (Equi-X, proposal 327) and strict tsconfig flags
across all packages. PoW is a strong future core candidate — pure,
deterministic, arithmetic-heavy — so the rebase is worth doing before
planning further conversion work.

---

## Reproducing the probe

The migration probe is checked in at
[`../scripts/migration-probe.sh`](../scripts/migration-probe.sh). It
runs every `src/*.ts` through a _given_ Thales binary and reports a
per-file emit table, without touching the committed pin.

```bash
# 1. Get a Lean toolchain matching the Thales you want to test.
#    (In sandboxes where release.lean-lang.org is unreachable, download
#    the tarball from the lean4 GitHub releases and `elan toolchain link`
#    it, rather than letting elan resolve the toolchain itself.)

# 2. Build the candidate Thales.
git clone https://github.com/jessealama/thales.git /tmp/thales-check
cd /tmp/thales-check && lake build thales

# 3. Probe emit.
THALES_BIN=/tmp/thales-check/.lake/build/bin/thales \
  bash packages/core/scripts/migration-probe.sh

# 4. Probe the proofs: copy packages/core to a scratch dir, point its
#    lakefile at the local Thales checkout, drop the probe's emitted
#    Lean into Generated/, bump lean-toolchain, and `lake build`.
```

Step 4 is what distinguishes "still emits" from "still verifies" — and
they are not the same question, as F2 shows.
