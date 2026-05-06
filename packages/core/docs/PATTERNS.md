# `tor-core` patterns

Conventions, recipes, and workarounds for adding to the verified core.
This file captures what 20 modules of trial-and-error converged on so
the next contributor doesn't re-discover them.

Where a convention is a workaround for a Thales 0.5 limitation, the
relevant draft in [`docs/thales-issues.md`](thales-issues.md) is cited
in parentheses.

---

## File layout

```
src/<camelCase>.ts         ← Thales subset, also valid TS
Generated/<PascalCase>.lean ← emitted by Thales (gitignored)
Spec/<PascalCase>.lean      ← hand-written theorems
```

Filename → Lean-module-name conversion: Thales pascalises the source
basename (`exitPolicy.ts` → `ExitPolicy.lean`, `kcpHeader.ts` →
`KcpHeader.lean`). Mirror that pascalisation when naming the matching
`Spec/` file.

In `Spec/<X>.lean`:

```lean
import Generated.<X>
import Thales.TS.Runtime
open Thales.TS

namespace Spec.<X>
open _root_.<X>           -- `_root_` is needed; `open <X>` would collide
                          -- with the surrounding `Spec.<X>` namespace.

deriving instance DecidableEq for <Type1>
deriving instance DecidableEq for <Type2>
-- ... etc, one for each emitted inductive you'll prove against
```

`deriving instance DecidableEq` is required for every emitted type that
appears in a `decide`-closed theorem. Thales emits `deriving Repr` only;
without explicit `DecidableEq`, `decide` can't reduce equalities.

---

## Type shapes

### Discriminated unions, not interfaces, for anything you construct

```ts
// ✗ broken: single-record `type` aliases collapse to `abbrev := Unit`
//   in the emitted Lean (Issue 2). Object literals on `interface`
//   types emit `(unsupported expr)` (Issue 3).
type PortRange = { start: bigint; endPort: bigint };

// ✓ works for *consuming* the value but not for constructing it
interface PortRange {
  start: bigint;
  endPort: bigint;
}

// ✓ works for both — the emitter handles DU constructor expressions
type PortRange = { kind: 'range'; start: bigint; endPort: bigint };
```

Rule of thumb: if any function in the verified core needs to build a
value of the type, use a multi-arm DU. Single-arm DU `type X = { kind:
'…'; … }` collapses to `Unit` just like the bare `type X = { … }`
form.

### Multi-output return types: DUs, not tuples

```ts
// ✗ tuples emit as Lean `Array`, not `Prod` (Issue 7)
function trySplit(n: bigint, bs: ByteList): [ByteList, ByteList] | null {
  ...
}

// ✓ DU result with named fields
type SplitResult =
  | { kind: 'ok'; taken: ByteList; rest: ByteList }
  | { kind: 'short' };
```

The DU shape is also self-documenting in proofs — every theorem
mentions `.ok` / `.short` instead of "the first element of the
returned tuple".

### Avoid Lean reserved-keyword field names

Thales emits TS field names verbatim into Lean structs. The 11 known
collisions are: `match`, `where`, `mut`, `fun`, `structure`,
`inductive`, `theorem`, `section`, `namespace`, `then`, `end` (Issue
1). Rename on the TS side. Example: `endPort` not `end` for a port
range's upper bound.

---

## Function shapes

### `bigint`, not `number`, for integer arithmetic

`number` maps to Lean `Float`; `bigint` maps to `Int`. Bit-exact wire
arithmetic is wrong over `Float`. Use `bigint` for every wire integer
field, byte value, sequence number, length, code point.

The TS-side seam adapter does `BigInt(x)` at the boundary.

### Avoid bitwise operators on bigint

Thales 0.5 doesn't lower `&`, `|`, `<<`, `>>` on bigint. Use
arithmetic equivalents:

```ts
// b is a byte (0..255); extract the high bit
const highBit = b >= 128n;
// b's low 7 bits
const low7 = b % 128n;
// b's low 6 bits
const low6 = b % 64n;
// shift left by 7 = multiply by 128
const shifted = x * 128n;
```

See `encapsulationPrefix.ts` for a worked example with non-trivial
bit packing.

### Switch only on a parameter

Switching on anything else fails or silently emits `()`:

```ts
// ✗ silent emit failure (Issue 6) — the switch body becomes `()`
//   and Lean rejects with a type mismatch
function isRetryable(r: RelayEndReason): boolean {
  switch (getStreamRetryBehavior(r).kind) {
    case 'retry_circuit': return true;
    ...
  }
}

// ✗ same — `const x = …` then `switch (x.kind)` is also broken
function f(r: T): U {
  const x = compute(r);
  switch (x.kind) { ... }
}

// ✓ switch on the parameter directly; if you need to dispatch on a
//   computed result, hoist into a helper that takes the result as a
//   parameter
function helper(b: Behavior): boolean { switch (b.kind) { ... } }
function isRetryable(r: RelayEndReason): boolean {
  return helper(getStreamRetryBehavior(r));
}
```

### Bind to `const` before constructing a DU value

Field access on a switch-narrowed DU works fine in arithmetic and
direct return positions, but **inside a DU constructor expression** the
emitted Lean has the wrong shape (Issue 8):

```ts
// ✗ emitted Lean has `r.value` where it should have the bound name
function bumpVal(r: Result): Result {
  switch (r.kind) {
    case 'ok':
      return { kind: 'ok', value: r.value + 1n }; // ← broken
    case 'err':
      return { kind: 'err' };
  }
}

// ✓ bind first, then construct using the const
function bumpVal(r: Result): Result {
  switch (r.kind) {
    case 'ok': {
      const v = r.value;
      return { kind: 'ok', value: v + 1n };
    }
    case 'err':
      return { kind: 'err' };
  }
}
```

This pattern is mechanical: any time a `case` body builds a DU value
from a field of the discriminant, bind the field first.

### Don't return `T | null` from a function-call composition

Thales wraps the call site in an extra `.some` (Issue 12):

```ts
// ✗ unwrap returns `bigint | null`; the call site is wrapped again
function unwrap(acc: MaxAcc): bigint | null { ... }
function f(): bigint | null {
  return unwrap(compute());  // ← emits `(.some (unwrap …))`, wrong type
}

// ✓ either expose the DU directly to the seam (let it unwrap) or
//   inline the unwrap with direct narrowing
function f(): bigint | null {
  const acc = compute();
  if (acc.kind === 'none') return null;
  return acc.value;
}
```

### Don't use `T | null` as an _intermediate_ accumulator

Null-narrowing through `if (x === null) return …` doesn't propagate
to subsequent comparisons (Issue 11):

```ts
// ✗ even with the early return, Thales sees `current` as
//   `bigint | null` at the comparison
function updateMax(current: bigint | null, c: bigint): bigint {
  if (current === null) return c;
  if (current >= c) return current; // ← TS2322
  return c;
}

// ✓ use a DU accumulator, switch on its kind, do the comparison in
//   the inline value-bearing branch
type MaxAcc = { kind: 'none' } | { kind: 'some'; value: bigint };
function updateMax(current: MaxAcc, c: bigint): MaxAcc {
  switch (current.kind) {
    case 'none':
      return { kind: 'some', value: c };
    case 'some': {
      const v = current.value;
      if (v >= c) return current;
      return { kind: 'some', value: c };
    }
  }
}
```

### Per-state helpers for state-machine `step` functions

A multi-state, multi-input transition function nested as one big
`switch (state.kind) { case: switch (input.kind) { ... } }` hits
Issue 6. Factor into one helper per state and let `step` dispatch:

```ts
function stepFromOpen(input: Input): State { switch (input.kind) { ... } }
function stepFromClosed(input: Input): State { switch (input.kind) { ... } }

function step(state: State, input: Input): State {
  switch (state.kind) {
    case 'open':
      return stepFromOpen(input);
    case 'closed': {
      const reason = state.reason;
      return stepFromClosed(reason, input);
    }
  }
}
```

This is the shape every state machine in core uses
(`channelState.ts`, `circuitState.ts`, `streamState.ts`,
`hsClientState.ts`, `hsHostState.ts`).

### Avoid case-fallthrough; spell out each case

```ts
// ✗ Thales' subset checker doesn't reliably handle TS fall-through
case 'A':
case 'B':
  return true;
case 'C':
  return false;

// ✓ explicit return per case
case 'A': return true;
case 'B': return true;
case 'C': return false;
```

Verbose but unambiguous.

---

## Recursion shapes

### Structural recursion only for `@total`

`@total` requires Lean's structural-recursion checker to accept the
function. Lean recognises structural recursion on inductive types:
recursing on `bs.tail` where `bs` is a `ByteList` cons cell is fine.

### Counter arguments are OK alongside structural recursion

Lean accepts a recursive call like `f(state, list.tail, n - 1n)` as
long as the _structural_ arg (`list.tail`) is smaller than the
discriminant (`list`). The numeric counter alongside is fine.
`encapsulationPrefix.ts`'s `continuePrefix` uses this pattern.

### Don't recurse on a numeric argument alone

`@decreasing` is parsed but ignored (Issue 9), and the resulting
`partial def` fails Lean's `Nonempty` check on user inductives (Issue
10). So `function f(n: bigint): MyType { if (n <= 0) return base;
return f(n - 1); }` doesn't work. Restructure to recurse on a list,
or wait for the upstream fix.

This blocks: any encoder that emits N bytes (`encodeUintBE`,
`bigIntToBytesLE`), `modPow` / `modInverse`, etc.

---

## Spec / Lean recipes

### Tactics available

This Lean project depends on `Thales` and (transitively) `batteries`
and `Regex`. **Mathlib is not a dependency** — pulling it in would
balloon CI. So:

| Want…                            | Available                                                                                          | Not available          |
| -------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------- |
| Linear arithmetic                | `omega`                                                                                            | `linarith`, `polyrith` |
| Polynomial equality              | (none — manual)                                                                                    | `ring`, `ring_nf`      |
| Case-split on `if`               | `by_cases h : …`                                                                                   | `split_ifs`            |
| Case-split on a finite Int range | `rcases` over `omega`-derived disjunction                                                          | `interval_cases`       |
| Pattern match on Int             | `match` syntax                                                                                     | `fin_cases`            |
| Definitional equality            | `rfl`, `decide`                                                                                    |                        |
| Goal manipulation                | `simp`, `simp only`, `rw`, `unfold`, `apply`, `intro`, `cases`, `induction`, `obtain`, `injection` |                        |

Recipe for a finite Int case-split:

```lean
have henum : c = 1 ∨ c = 2 ∨ c = 3 := by omega
rcases henum with h | h | h <;> subst h <;> decide
```

Recipe for if-splitting:

```lean
by_cases h : 0 ≤ x
· rw [if_pos h]; ...
· rw [if_neg h]; ...
```

### `decide` needs concrete values

`decide` reduces only when the goal contains no free variables. With
free variables, use `rfl` (for definitional equalities) or `simp` with
explicit unfolds:

```lean
-- ✗ free variable `r`, decide can't reduce
theorem foo (r : Int) : isClosed (.closed r) = true := by decide

-- ✓ rfl works because the body of `isClosed (.closed r)` reduces
--   regardless of r
theorem foo (r : Int) : isClosed (.closed r) = true := rfl
```

### Constants are `def`s, not literals

Spec constants emitted by Thales (e.g.
`CIRCUIT_SENDME_INCREMENT = 100n`) become `def`s in Lean, not literal
`100`. `decide` reduces through them automatically; explicit `simp`
or `unfold` requires naming them in the simp set:

```lean
simp [step, stepFromAwaitingVersions, REASON_UNEXPECTED_CELL]
```

### Decidable equality

Add `deriving instance DecidableEq for <Type>` near the top of every
`Spec/*.lean`, once for each emitted type that appears in a
`decide`-closed equality or in a `cases h : … with` over the type's
constructors. Thales-emitted types include only `deriving Repr`.

---

## Adding a new module

1. Pick a single conceptual unit (one DU, one state machine, one set
   of related arithmetic helpers).
2. Write `src/<name>.ts`. Stick to the type/function shapes above.
3. Run locally:
   ```bash
   cd packages/core
   bash scripts/verify.sh   # transpiles src/* → Generated/* and lake builds
   ```
4. If Thales rejects, the error usually maps to one of the issues in
   `docs/thales-issues.md` — find the workaround there. If it's new,
   add it to the doc as a new draft.
5. Write `Spec/<Name>.lean`. Start with the easy theorems (concrete
   values, basic unfoldings), then layer up to invariants and
   round-trips. Use the recipes above when a tactic isn't available.
6. Run `bash scripts/verify.sh` again — `lake build` fails the
   verification if any theorem doesn't kernel-check.
7. Run `npx prettier --write src/<name>.ts` to match repo style.
8. Update the table in `README.md` so the count stays accurate.
9. Commit.

---

## When to skip a module

The verified surface is at a sensible plateau (~20 modules / ~360
theorems covering wire vocabulary, byte primitives, exit-policy
evaluation, sequence-number arithmetic, all five protocol-state
machines, flow control, and prefix decoders). Slices that hit any of
the following are blocked until upstream Thales fixes land:

- **Imports/exports between modules** (Issue 5) — needed to compose
  parsers, share types across files, and integrate with the
  non-verified shell. Until then, every verified file is
  self-contained and types like `ByteList` are duplicated where
  needed (with a `Mirrored from bytes.ts` comment).
- **Encoders recursing on a numeric length** (Issues 9 + 10) — blocks
  `bigIntToBytesLE`, `encodeUintBE`, `modPow`, `modInverse`, KCP and
  SMUX encoders, etc.
- **String stdlib** (Issue 4) — `String.split`, `String.indexOf`,
  `parseInt`, etc. aren't in the prelude. Blocks
  `parseExitPolicySummary`, microdesc parser, consensus parser, HTTP
  parser.
- **Crypto FFI declarations** — calling SHA-3 / SHAKE256 / Curve25519
  from verified code needs Lean-side `extern` declarations the
  Thales runtime doesn't supply.

Don't try to work around these one slice at a time — file the
upstream issue (or extend the existing draft in `thales-issues.md`)
and move on.
